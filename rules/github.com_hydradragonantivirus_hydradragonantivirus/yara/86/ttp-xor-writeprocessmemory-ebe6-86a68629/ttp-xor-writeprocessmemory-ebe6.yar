rule TTP_XOR_WriteProcessMemory_ebe6 {
  strings:
    $key_ebe6 = { bc 94 [2] 8e b6 [2] 88 83 [2] a6 83 [2] 99 9f }

  condition:
    any of them
}