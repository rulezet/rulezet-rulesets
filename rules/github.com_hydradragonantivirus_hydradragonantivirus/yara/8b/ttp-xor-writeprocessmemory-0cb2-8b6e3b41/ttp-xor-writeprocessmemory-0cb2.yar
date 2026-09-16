rule TTP_XOR_WriteProcessMemory_0cb2 {
  strings:
    $key_0cb2 = { 5b c0 [2] 69 e2 [2] 6f d7 [2] 41 d7 [2] 7e cb }

  condition:
    any of them
}