rule TTP_XOR_WriteProcessMemory_fff5 {
  strings:
    $key_fff5 = { a8 87 [2] 9a a5 [2] 9c 90 [2] b2 90 [2] 8d 8c }

  condition:
    any of them
}