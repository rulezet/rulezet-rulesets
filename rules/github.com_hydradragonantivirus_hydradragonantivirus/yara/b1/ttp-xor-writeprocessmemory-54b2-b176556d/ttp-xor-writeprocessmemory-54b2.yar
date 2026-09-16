rule TTP_XOR_WriteProcessMemory_54b2 {
  strings:
    $key_54b2 = { 03 c0 [2] 31 e2 [2] 37 d7 [2] 19 d7 [2] 26 cb }

  condition:
    any of them
}