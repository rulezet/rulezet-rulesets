rule TTP_XOR_WriteProcessMemory_65e5 {
  strings:
    $key_65e5 = { 32 97 [2] 00 b5 [2] 06 80 [2] 28 80 [2] 17 9c }

  condition:
    any of them
}