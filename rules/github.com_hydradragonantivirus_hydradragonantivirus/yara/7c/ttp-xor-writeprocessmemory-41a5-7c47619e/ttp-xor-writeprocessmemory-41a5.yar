rule TTP_XOR_WriteProcessMemory_41a5 {
  strings:
    $key_41a5 = { 16 d7 [2] 24 f5 [2] 22 c0 [2] 0c c0 [2] 33 dc }

  condition:
    any of them
}