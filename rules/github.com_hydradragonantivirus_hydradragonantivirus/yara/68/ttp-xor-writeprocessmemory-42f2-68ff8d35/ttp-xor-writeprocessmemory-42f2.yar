rule TTP_XOR_WriteProcessMemory_42f2 {
  strings:
    $key_42f2 = { 15 80 [2] 27 a2 [2] 21 97 [2] 0f 97 [2] 30 8b }

  condition:
    any of them
}