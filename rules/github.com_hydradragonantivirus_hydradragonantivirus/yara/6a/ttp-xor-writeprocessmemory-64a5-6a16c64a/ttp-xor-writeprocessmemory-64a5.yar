rule TTP_XOR_WriteProcessMemory_64a5 {
  strings:
    $key_64a5 = { 33 d7 [2] 01 f5 [2] 07 c0 [2] 29 c0 [2] 16 dc }

  condition:
    any of them
}