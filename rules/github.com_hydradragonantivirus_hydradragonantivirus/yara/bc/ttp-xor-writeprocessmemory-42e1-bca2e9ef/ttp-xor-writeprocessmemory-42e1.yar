rule TTP_XOR_WriteProcessMemory_42e1 {
  strings:
    $key_42e1 = { 15 93 [2] 27 b1 [2] 21 84 [2] 0f 84 [2] 30 98 }

  condition:
    any of them
}