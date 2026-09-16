rule TTP_XOR_WriteProcessMemory_e2a5 {
  strings:
    $key_e2a5 = { b5 d7 [2] 87 f5 [2] 81 c0 [2] af c0 [2] 90 dc }

  condition:
    any of them
}