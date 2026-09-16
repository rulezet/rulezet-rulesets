rule TTP_XOR_WriteProcessMemory_1a15 {
  strings:
    $key_1a15 = { 4d 67 [2] 7f 45 [2] 79 70 [2] 57 70 [2] 68 6c }

  condition:
    any of them
}