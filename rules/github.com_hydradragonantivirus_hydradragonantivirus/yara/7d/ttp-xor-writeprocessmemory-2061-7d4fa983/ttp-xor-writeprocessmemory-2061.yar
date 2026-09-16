rule TTP_XOR_WriteProcessMemory_2061 {
  strings:
    $key_2061 = { 77 13 [2] 45 31 [2] 43 04 [2] 6d 04 [2] 52 18 }

  condition:
    any of them
}