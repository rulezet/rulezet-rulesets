rule TTP_XOR_WriteProcessMemory_51a4 {
  strings:
    $key_51a4 = { 06 d6 [2] 34 f4 [2] 32 c1 [2] 1c c1 [2] 23 dd }

  condition:
    any of them
}