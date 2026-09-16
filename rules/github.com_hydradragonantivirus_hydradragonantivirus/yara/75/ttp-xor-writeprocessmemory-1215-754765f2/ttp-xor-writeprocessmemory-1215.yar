rule TTP_XOR_WriteProcessMemory_1215 {
  strings:
    $key_1215 = { 45 67 [2] 77 45 [2] 71 70 [2] 5f 70 [2] 60 6c }

  condition:
    any of them
}