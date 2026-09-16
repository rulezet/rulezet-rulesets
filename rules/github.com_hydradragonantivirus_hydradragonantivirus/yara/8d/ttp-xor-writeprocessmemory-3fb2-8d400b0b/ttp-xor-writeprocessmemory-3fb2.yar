rule TTP_XOR_WriteProcessMemory_3fb2 {
  strings:
    $key_3fb2 = { 68 c0 [2] 5a e2 [2] 5c d7 [2] 72 d7 [2] 4d cb }

  condition:
    any of them
}