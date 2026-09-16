rule TTP_XOR_WriteProcessMemory_dc47 {
  strings:
    $key_dc47 = { 8b 35 [2] b9 17 [2] bf 22 [2] 91 22 [2] ae 3e }

  condition:
    any of them
}