rule TTP_XOR_WriteProcessMemory_1433 {
  strings:
    $key_1433 = { 43 41 [2] 71 63 [2] 77 56 [2] 59 56 [2] 66 4a }

  condition:
    any of them
}