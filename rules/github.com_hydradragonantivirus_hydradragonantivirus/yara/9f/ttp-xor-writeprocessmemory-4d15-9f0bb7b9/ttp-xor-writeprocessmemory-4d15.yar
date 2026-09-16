rule TTP_XOR_WriteProcessMemory_4d15 {
  strings:
    $key_4d15 = { 1a 67 [2] 28 45 [2] 2e 70 [2] 00 70 [2] 3f 6c }

  condition:
    any of them
}