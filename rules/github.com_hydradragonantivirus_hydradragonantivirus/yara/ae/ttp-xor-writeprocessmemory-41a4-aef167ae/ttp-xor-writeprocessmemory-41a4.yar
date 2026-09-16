rule TTP_XOR_WriteProcessMemory_41a4 {
  strings:
    $key_41a4 = { 16 d6 [2] 24 f4 [2] 22 c1 [2] 0c c1 [2] 33 dd }

  condition:
    any of them
}