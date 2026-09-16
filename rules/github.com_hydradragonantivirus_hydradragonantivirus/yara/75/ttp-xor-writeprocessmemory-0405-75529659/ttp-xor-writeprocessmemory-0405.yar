rule TTP_XOR_WriteProcessMemory_0405 {
  strings:
    $key_0405 = { 53 77 [2] 61 55 [2] 67 60 [2] 49 60 [2] 76 7c }

  condition:
    any of them
}