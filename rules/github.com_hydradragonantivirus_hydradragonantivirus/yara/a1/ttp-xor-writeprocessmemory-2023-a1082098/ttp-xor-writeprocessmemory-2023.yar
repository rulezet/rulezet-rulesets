rule TTP_XOR_WriteProcessMemory_2023 {
  strings:
    $key_2023 = { 77 51 [2] 45 73 [2] 43 46 [2] 6d 46 [2] 52 5a }

  condition:
    any of them
}