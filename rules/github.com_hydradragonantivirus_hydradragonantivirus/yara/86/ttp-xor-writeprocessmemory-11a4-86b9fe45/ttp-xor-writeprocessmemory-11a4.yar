rule TTP_XOR_WriteProcessMemory_11a4 {
  strings:
    $key_11a4 = { 46 d6 [2] 74 f4 [2] 72 c1 [2] 5c c1 [2] 63 dd }

  condition:
    any of them
}