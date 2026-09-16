rule TTP_XOR_WriteProcessMemory_37a5 {
  strings:
    $key_37a5 = { 60 d7 [2] 52 f5 [2] 54 c0 [2] 7a c0 [2] 45 dc }

  condition:
    any of them
}