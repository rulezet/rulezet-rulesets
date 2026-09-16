rule TTP_XOR_WriteProcessMemory_3015 {
  strings:
    $key_3015 = { 67 67 [2] 55 45 [2] 53 70 [2] 7d 70 [2] 42 6c }

  condition:
    any of them
}