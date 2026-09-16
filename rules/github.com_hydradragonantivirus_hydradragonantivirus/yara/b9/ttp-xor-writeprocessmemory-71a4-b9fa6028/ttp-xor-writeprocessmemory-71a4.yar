rule TTP_XOR_WriteProcessMemory_71a4 {
  strings:
    $key_71a4 = { 26 d6 [2] 14 f4 [2] 12 c1 [2] 3c c1 [2] 03 dd }

  condition:
    any of them
}