rule TTP_XOR_WriteProcessMemory_f5f9 {
  strings:
    $key_f5f9 = { a2 8b [2] 90 a9 [2] 96 9c [2] b8 9c [2] 87 80 }

  condition:
    any of them
}