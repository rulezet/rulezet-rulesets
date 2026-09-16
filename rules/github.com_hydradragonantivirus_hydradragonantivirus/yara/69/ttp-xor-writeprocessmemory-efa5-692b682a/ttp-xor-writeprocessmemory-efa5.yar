rule TTP_XOR_WriteProcessMemory_efa5 {
  strings:
    $key_efa5 = { b8 d7 [2] 8a f5 [2] 8c c0 [2] a2 c0 [2] 9d dc }

  condition:
    any of them
}