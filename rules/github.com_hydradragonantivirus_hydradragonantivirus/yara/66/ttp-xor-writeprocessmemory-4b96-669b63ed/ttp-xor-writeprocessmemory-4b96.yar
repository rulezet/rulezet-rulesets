rule TTP_XOR_WriteProcessMemory_4b96 {
  strings:
    $key_4b96 = { 1c e4 [2] 2e c6 [2] 28 f3 [2] 06 f3 [2] 39 ef }

  condition:
    any of them
}