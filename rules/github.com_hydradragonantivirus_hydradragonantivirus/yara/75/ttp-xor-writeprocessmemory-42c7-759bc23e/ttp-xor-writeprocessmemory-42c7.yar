rule TTP_XOR_WriteProcessMemory_42c7 {
  strings:
    $key_42c7 = { 15 b5 [2] 27 97 [2] 21 a2 [2] 0f a2 [2] 30 be }

  condition:
    any of them
}