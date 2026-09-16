rule TTP_XOR_WriteProcessMemory_5537 {
  strings:
    $key_5537 = { 02 45 [2] 30 67 [2] 36 52 [2] 18 52 [2] 27 4e }

  condition:
    any of them
}