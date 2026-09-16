rule TTP_XOR_WriteProcessMemory_05a5 {
  strings:
    $key_05a5 = { 52 d7 [2] 60 f5 [2] 66 c0 [2] 48 c0 [2] 77 dc }

  condition:
    any of them
}