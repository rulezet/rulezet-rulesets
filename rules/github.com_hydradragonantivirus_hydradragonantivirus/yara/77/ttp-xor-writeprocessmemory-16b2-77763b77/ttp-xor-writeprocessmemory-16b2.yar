rule TTP_XOR_WriteProcessMemory_16b2 {
  strings:
    $key_16b2 = { 41 c0 [2] 73 e2 [2] 75 d7 [2] 5b d7 [2] 64 cb }

  condition:
    any of them
}