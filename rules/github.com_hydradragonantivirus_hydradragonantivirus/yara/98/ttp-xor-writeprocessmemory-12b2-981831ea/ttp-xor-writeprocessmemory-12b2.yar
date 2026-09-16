rule TTP_XOR_WriteProcessMemory_12b2 {
  strings:
    $key_12b2 = { 45 c0 [2] 77 e2 [2] 71 d7 [2] 5f d7 [2] 60 cb }

  condition:
    any of them
}