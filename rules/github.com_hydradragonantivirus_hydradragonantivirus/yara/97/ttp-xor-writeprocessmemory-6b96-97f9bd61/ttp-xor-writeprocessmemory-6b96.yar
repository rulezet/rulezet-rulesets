rule TTP_XOR_WriteProcessMemory_6b96 {
  strings:
    $key_6b96 = { 3c e4 [2] 0e c6 [2] 08 f3 [2] 26 f3 [2] 19 ef }

  condition:
    any of them
}