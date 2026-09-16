rule TTP_XOR_WriteProcessMemory_2077 {
  strings:
    $key_2077 = { 77 05 [2] 45 27 [2] 43 12 [2] 6d 12 [2] 52 0e }

  condition:
    any of them
}