rule TTP_XOR_WriteProcessMemory_7cb1 {
  strings:
    $key_7cb1 = { 2b c3 [2] 19 e1 [2] 1f d4 [2] 31 d4 [2] 0e c8 }

  condition:
    any of them
}