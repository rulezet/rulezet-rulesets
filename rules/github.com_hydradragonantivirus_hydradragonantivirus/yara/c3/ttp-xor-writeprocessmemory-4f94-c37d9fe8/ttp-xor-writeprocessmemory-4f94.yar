rule TTP_XOR_WriteProcessMemory_4f94 {
  strings:
    $key_4f94 = { 18 e6 [2] 2a c4 [2] 2c f1 [2] 02 f1 [2] 3d ed }

  condition:
    any of them
}