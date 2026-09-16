rule TTP_XOR_WriteProcessMemory_2a25 {
  strings:
    $key_2a25 = { 7d 57 [2] 4f 75 [2] 49 40 [2] 67 40 [2] 58 5c }

  condition:
    any of them
}