rule TTP_XOR_WriteProcessMemory_b2a5 {
  strings:
    $key_b2a5 = { e5 d7 [2] d7 f5 [2] d1 c0 [2] ff c0 [2] c0 dc }

  condition:
    any of them
}