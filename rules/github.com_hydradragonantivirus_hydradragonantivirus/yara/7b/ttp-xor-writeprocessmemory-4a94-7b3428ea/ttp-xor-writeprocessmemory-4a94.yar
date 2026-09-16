rule TTP_XOR_WriteProcessMemory_4a94 {
  strings:
    $key_4a94 = { 1d e6 [2] 2f c4 [2] 29 f1 [2] 07 f1 [2] 38 ed }

  condition:
    any of them
}