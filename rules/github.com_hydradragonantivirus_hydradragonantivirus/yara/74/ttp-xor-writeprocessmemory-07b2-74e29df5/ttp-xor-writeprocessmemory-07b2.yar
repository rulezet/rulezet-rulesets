rule TTP_XOR_WriteProcessMemory_07b2 {
  strings:
    $key_07b2 = { 50 c0 [2] 62 e2 [2] 64 d7 [2] 4a d7 [2] 75 cb }

  condition:
    any of them
}