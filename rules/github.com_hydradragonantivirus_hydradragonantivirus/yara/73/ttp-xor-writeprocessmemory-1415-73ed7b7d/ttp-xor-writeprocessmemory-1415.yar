rule TTP_XOR_WriteProcessMemory_1415 {
  strings:
    $key_1415 = { 43 67 [2] 71 45 [2] 77 70 [2] 59 70 [2] 66 6c }

  condition:
    any of them
}