rule TTP_XOR_WriteProcessMemory_4ae5 {
  strings:
    $key_4ae5 = { 1d 97 [2] 2f b5 [2] 29 80 [2] 07 80 [2] 38 9c }

  condition:
    any of them
}