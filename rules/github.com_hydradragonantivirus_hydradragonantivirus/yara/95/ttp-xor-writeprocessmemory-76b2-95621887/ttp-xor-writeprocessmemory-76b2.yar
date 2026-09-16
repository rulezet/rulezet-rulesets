rule TTP_XOR_WriteProcessMemory_76b2 {
  strings:
    $key_76b2 = { 21 c0 [2] 13 e2 [2] 15 d7 [2] 3b d7 [2] 04 cb }

  condition:
    any of them
}