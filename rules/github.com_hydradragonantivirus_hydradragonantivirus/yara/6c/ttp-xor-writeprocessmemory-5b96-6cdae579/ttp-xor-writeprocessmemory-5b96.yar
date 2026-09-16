rule TTP_XOR_WriteProcessMemory_5b96 {
  strings:
    $key_5b96 = { 0c e4 [2] 3e c6 [2] 38 f3 [2] 16 f3 [2] 29 ef }

  condition:
    any of them
}