rule TTP_XOR_WriteProcessMemory_dc07 {
  strings:
    $key_dc07 = { 8b 75 [2] b9 57 [2] bf 62 [2] 91 62 [2] ae 7e }

  condition:
    any of them
}