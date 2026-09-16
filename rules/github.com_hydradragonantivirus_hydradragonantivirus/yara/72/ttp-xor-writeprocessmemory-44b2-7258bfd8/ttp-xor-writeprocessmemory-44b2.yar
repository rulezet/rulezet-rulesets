rule TTP_XOR_WriteProcessMemory_44b2 {
  strings:
    $key_44b2 = { 13 c0 [2] 21 e2 [2] 27 d7 [2] 09 d7 [2] 36 cb }

  condition:
    any of them
}