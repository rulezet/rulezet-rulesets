rule TTP_XOR_WriteProcessMemory_0af5 {
  strings:
    $key_0af5 = { 5d 87 [2] 6f a5 [2] 69 90 [2] 47 90 [2] 78 8c }

  condition:
    any of them
}