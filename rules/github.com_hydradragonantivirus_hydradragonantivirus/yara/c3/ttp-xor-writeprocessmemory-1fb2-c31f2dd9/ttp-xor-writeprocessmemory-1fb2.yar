rule TTP_XOR_WriteProcessMemory_1fb2 {
  strings:
    $key_1fb2 = { 48 c0 [2] 7a e2 [2] 7c d7 [2] 52 d7 [2] 6d cb }

  condition:
    any of them
}