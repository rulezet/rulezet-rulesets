rule TTP_XOR_WriteProcessMemory_1417 {
  strings:
    $key_1417 = { 43 65 [2] 71 47 [2] 77 72 [2] 59 72 [2] 66 6e }

  condition:
    any of them
}