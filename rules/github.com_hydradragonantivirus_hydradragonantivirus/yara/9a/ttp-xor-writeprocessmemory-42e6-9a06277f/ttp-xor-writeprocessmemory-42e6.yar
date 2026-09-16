rule TTP_XOR_WriteProcessMemory_42e6 {
  strings:
    $key_42e6 = { 15 94 [2] 27 b6 [2] 21 83 [2] 0f 83 [2] 30 9f }

  condition:
    any of them
}