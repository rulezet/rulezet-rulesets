rule TTP_XOR_WriteProcessMemory_4ab2 {
  strings:
    $key_4ab2 = { 1d c0 [2] 2f e2 [2] 29 d7 [2] 07 d7 [2] 38 cb }

  condition:
    any of them
}