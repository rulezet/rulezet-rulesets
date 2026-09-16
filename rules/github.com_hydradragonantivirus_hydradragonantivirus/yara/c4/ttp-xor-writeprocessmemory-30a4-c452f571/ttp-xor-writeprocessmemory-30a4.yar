rule TTP_XOR_WriteProcessMemory_30a4 {
  strings:
    $key_30a4 = { 67 d6 [2] 55 f4 [2] 53 c1 [2] 7d c1 [2] 42 dd }

  condition:
    any of them
}