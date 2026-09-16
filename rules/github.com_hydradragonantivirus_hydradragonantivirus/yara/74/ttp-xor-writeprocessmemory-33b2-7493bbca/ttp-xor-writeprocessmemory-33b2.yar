rule TTP_XOR_WriteProcessMemory_33b2 {
  strings:
    $key_33b2 = { 64 c0 [2] 56 e2 [2] 50 d7 [2] 7e d7 [2] 41 cb }

  condition:
    any of them
}