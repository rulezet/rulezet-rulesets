rule TTP_XOR_WriteProcessMemory_dc41 {
  strings:
    $key_dc41 = { 8b 33 [2] b9 11 [2] bf 24 [2] 91 24 [2] ae 38 }

  condition:
    any of them
}