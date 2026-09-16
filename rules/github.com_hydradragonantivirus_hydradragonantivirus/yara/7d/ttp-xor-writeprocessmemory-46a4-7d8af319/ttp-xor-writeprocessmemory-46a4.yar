rule TTP_XOR_WriteProcessMemory_46a4 {
  strings:
    $key_46a4 = { 11 d6 [2] 23 f4 [2] 25 c1 [2] 0b c1 [2] 34 dd }

  condition:
    any of them
}