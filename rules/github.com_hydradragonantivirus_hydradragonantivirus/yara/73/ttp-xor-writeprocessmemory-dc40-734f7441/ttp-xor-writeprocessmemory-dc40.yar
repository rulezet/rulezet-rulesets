rule TTP_XOR_WriteProcessMemory_dc40 {
  strings:
    $key_dc40 = { 8b 32 [2] b9 10 [2] bf 25 [2] 91 25 [2] ae 39 }

  condition:
    any of them
}