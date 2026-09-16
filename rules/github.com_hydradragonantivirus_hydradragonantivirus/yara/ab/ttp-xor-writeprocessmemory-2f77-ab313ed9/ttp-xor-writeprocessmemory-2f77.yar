rule TTP_XOR_WriteProcessMemory_2f77 {
  strings:
    $key_2f77 = { 78 05 [2] 4a 27 [2] 4c 12 [2] 62 12 [2] 5d 0e }

  condition:
    any of them
}