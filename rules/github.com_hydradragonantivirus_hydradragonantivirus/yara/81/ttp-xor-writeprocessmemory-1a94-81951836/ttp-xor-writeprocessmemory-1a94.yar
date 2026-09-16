rule TTP_XOR_WriteProcessMemory_1a94 {
  strings:
    $key_1a94 = { 4d e6 [2] 7f c4 [2] 79 f1 [2] 57 f1 [2] 68 ed }

  condition:
    any of them
}