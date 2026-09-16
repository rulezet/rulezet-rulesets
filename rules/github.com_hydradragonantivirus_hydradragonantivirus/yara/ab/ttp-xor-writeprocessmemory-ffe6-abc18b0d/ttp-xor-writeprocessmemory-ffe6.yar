rule TTP_XOR_WriteProcessMemory_ffe6 {
  strings:
    $key_ffe6 = { a8 94 [2] 9a b6 [2] 9c 83 [2] b2 83 [2] 8d 9f }

  condition:
    any of them
}