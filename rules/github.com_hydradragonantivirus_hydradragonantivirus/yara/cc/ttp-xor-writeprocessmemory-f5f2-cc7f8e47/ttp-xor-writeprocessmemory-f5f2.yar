rule TTP_XOR_WriteProcessMemory_f5f2 {
  strings:
    $key_f5f2 = { a2 80 [2] 90 a2 [2] 96 97 [2] b8 97 [2] 87 8b }

  condition:
    any of them
}