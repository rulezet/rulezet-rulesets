rule TTP_XOR_WriteProcessMemory_1435 {
  strings:
    $key_1435 = { 43 47 [2] 71 65 [2] 77 50 [2] 59 50 [2] 66 4c }

  condition:
    any of them
}