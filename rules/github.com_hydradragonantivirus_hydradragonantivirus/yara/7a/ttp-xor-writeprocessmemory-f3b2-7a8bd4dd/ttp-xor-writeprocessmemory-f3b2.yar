rule TTP_XOR_WriteProcessMemory_f3b2 {
  strings:
    $key_f3b2 = { a4 c0 [2] 96 e2 [2] 90 d7 [2] be d7 [2] 81 cb }

  condition:
    any of them
}