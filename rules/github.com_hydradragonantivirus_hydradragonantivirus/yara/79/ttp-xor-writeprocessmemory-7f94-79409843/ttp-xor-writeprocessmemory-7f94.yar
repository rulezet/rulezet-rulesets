rule TTP_XOR_WriteProcessMemory_7f94 {
  strings:
    $key_7f94 = { 28 e6 [2] 1a c4 [2] 1c f1 [2] 32 f1 [2] 0d ed }

  condition:
    any of them
}