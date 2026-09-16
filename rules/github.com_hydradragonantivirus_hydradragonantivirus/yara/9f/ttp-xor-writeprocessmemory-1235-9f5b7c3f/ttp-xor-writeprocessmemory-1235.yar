rule TTP_XOR_WriteProcessMemory_1235 {
  strings:
    $key_1235 = { 45 47 [2] 77 65 [2] 71 50 [2] 5f 50 [2] 60 4c }

  condition:
    any of them
}