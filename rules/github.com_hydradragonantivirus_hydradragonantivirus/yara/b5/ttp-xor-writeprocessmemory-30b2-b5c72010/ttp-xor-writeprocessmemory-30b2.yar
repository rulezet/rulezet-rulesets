rule TTP_XOR_WriteProcessMemory_30b2 {
  strings:
    $key_30b2 = { 67 c0 [2] 55 e2 [2] 53 d7 [2] 7d d7 [2] 42 cb }

  condition:
    any of them
}