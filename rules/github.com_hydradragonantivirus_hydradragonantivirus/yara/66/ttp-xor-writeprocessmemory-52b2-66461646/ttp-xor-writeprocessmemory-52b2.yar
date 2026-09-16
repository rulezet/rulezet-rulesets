rule TTP_XOR_WriteProcessMemory_52b2 {
  strings:
    $key_52b2 = { 05 c0 [2] 37 e2 [2] 31 d7 [2] 1f d7 [2] 20 cb }

  condition:
    any of them
}