rule TTP_XOR_WriteProcessMemory_61a5 {
  strings:
    $key_61a5 = { 36 d7 [2] 04 f5 [2] 02 c0 [2] 2c c0 [2] 13 dc }

  condition:
    any of them
}