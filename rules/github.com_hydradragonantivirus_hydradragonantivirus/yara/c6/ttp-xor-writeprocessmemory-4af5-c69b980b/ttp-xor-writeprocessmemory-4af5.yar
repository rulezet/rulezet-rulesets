rule TTP_XOR_WriteProcessMemory_4af5 {
  strings:
    $key_4af5 = { 1d 87 [2] 2f a5 [2] 29 90 [2] 07 90 [2] 38 8c }

  condition:
    any of them
}