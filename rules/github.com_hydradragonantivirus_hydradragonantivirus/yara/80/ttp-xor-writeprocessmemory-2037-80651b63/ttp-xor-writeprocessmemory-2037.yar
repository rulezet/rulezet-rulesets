rule TTP_XOR_WriteProcessMemory_2037 {
  strings:
    $key_2037 = { 77 45 [2] 45 67 [2] 43 52 [2] 6d 52 [2] 52 4e }

  condition:
    any of them
}