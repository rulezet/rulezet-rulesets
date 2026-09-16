rule TTP_XOR_WriteProcessMemory_37b2 {
  strings:
    $key_37b2 = { 60 c0 [2] 52 e2 [2] 54 d7 [2] 7a d7 [2] 45 cb }

  condition:
    any of them
}