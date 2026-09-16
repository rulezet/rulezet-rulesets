rule TTP_XOR_WriteProcessMemory_efa2 {
  strings:
    $key_efa2 = { b8 d0 [2] 8a f2 [2] 8c c7 [2] a2 c7 [2] 9d db }

  condition:
    any of them
}