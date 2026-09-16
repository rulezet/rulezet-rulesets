rule TTP_XOR_WriteProcessMemory_62a5 {
  strings:
    $key_62a5 = { 35 d7 [2] 07 f5 [2] 01 c0 [2] 2f c0 [2] 10 dc }

  condition:
    any of them
}