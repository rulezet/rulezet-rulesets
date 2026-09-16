rule TTP_XOR_WriteProcessMemory_dc10 {
  strings:
    $key_dc10 = { 8b 62 [2] b9 40 [2] bf 75 [2] 91 75 [2] ae 69 }

  condition:
    any of them
}