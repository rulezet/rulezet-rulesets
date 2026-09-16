rule TTP_XOR_WriteProcessMemory_2605 {
  strings:
    $key_2605 = { 71 77 [2] 43 55 [2] 45 60 [2] 6b 60 [2] 54 7c }

  condition:
    any of them
}