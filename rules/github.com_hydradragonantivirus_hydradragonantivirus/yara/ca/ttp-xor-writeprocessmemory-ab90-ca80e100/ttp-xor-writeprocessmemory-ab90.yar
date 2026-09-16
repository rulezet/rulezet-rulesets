rule TTP_XOR_WriteProcessMemory_ab90 {
  strings:
    $key_ab90 = { fc e2 [2] ce c0 [2] c8 f5 [2] e6 f5 [2] d9 e9 }

  condition:
    any of them
}