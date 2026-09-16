rule TTP_XOR_WriteProcessMemory_efa4 {
  strings:
    $key_efa4 = { b8 d6 [2] 8a f4 [2] 8c c1 [2] a2 c1 [2] 9d dd }

  condition:
    any of them
}