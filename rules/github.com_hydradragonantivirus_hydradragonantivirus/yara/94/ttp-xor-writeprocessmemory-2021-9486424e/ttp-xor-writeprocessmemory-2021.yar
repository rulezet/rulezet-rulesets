rule TTP_XOR_WriteProcessMemory_2021 {
  strings:
    $key_2021 = { 77 53 [2] 45 71 [2] 43 44 [2] 6d 44 [2] 52 58 }

  condition:
    any of them
}