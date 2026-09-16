rule TTP_XOR_WriteProcessMemory_90b2 {
  strings:
    $key_90b2 = { c7 c0 [2] f5 e2 [2] f3 d7 [2] dd d7 [2] e2 cb }

  condition:
    any of them
}