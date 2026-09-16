rule TTP_XOR_WriteProcessMemory_5a94 {
  strings:
    $key_5a94 = { 0d e6 [2] 3f c4 [2] 39 f1 [2] 17 f1 [2] 28 ed }

  condition:
    any of them
}