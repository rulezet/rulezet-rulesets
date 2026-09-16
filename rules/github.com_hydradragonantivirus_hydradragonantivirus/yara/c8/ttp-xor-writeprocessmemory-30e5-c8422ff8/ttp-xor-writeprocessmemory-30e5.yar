rule TTP_XOR_WriteProcessMemory_30e5 {
  strings:
    $key_30e5 = { 67 97 [2] 55 b5 [2] 53 80 [2] 7d 80 [2] 42 9c }

  condition:
    any of them
}