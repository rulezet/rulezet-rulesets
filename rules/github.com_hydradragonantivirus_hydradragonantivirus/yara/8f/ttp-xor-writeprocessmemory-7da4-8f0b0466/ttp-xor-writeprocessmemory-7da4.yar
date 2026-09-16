rule TTP_XOR_WriteProcessMemory_7da4 {
  strings:
    $key_7da4 = { 2a d6 [2] 18 f4 [2] 1e c1 [2] 30 c1 [2] 0f dd }

  condition:
    any of them
}