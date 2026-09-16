rule TTP_XOR_WriteProcessMemory_f526 {
  strings:
    $key_f526 = { a2 54 [2] 90 76 [2] 96 43 [2] b8 43 [2] 87 5f }

  condition:
    any of them
}