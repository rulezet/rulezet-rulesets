rule TTP_XOR_WriteProcessMemory_2a15 {
  strings:
    $key_2a15 = { 7d 67 [2] 4f 45 [2] 49 70 [2] 67 70 [2] 58 6c }

  condition:
    any of them
}