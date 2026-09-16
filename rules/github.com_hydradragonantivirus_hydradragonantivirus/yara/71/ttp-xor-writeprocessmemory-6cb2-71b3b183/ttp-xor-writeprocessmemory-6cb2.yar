rule TTP_XOR_WriteProcessMemory_6cb2 {
  strings:
    $key_6cb2 = { 3b c0 [2] 09 e2 [2] 0f d7 [2] 21 d7 [2] 1e cb }

  condition:
    any of them
}