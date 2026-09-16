rule TTP_XOR_WriteProcessMemory_5f94 {
  strings:
    $key_5f94 = { 08 e6 [2] 3a c4 [2] 3c f1 [2] 12 f1 [2] 2d ed }

  condition:
    any of them
}