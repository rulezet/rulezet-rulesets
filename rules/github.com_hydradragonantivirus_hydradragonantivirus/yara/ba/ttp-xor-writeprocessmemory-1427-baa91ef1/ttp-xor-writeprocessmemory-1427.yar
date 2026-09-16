rule TTP_XOR_WriteProcessMemory_1427 {
  strings:
    $key_1427 = { 43 55 [2] 71 77 [2] 77 42 [2] 59 42 [2] 66 5e }

  condition:
    any of them
}