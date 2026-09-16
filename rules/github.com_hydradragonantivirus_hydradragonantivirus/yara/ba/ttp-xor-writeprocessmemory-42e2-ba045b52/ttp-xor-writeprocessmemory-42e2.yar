rule TTP_XOR_WriteProcessMemory_42e2 {
  strings:
    $key_42e2 = { 15 90 [2] 27 b2 [2] 21 87 [2] 0f 87 [2] 30 9b }

  condition:
    any of them
}