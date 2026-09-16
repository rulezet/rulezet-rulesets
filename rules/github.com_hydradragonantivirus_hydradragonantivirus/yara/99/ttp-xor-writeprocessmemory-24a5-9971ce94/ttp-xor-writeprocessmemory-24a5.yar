rule TTP_XOR_WriteProcessMemory_24a5 {
  strings:
    $key_24a5 = { 73 d7 [2] 41 f5 [2] 47 c0 [2] 69 c0 [2] 56 dc }

  condition:
    any of them
}