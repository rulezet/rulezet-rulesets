rule TTP_XOR_WriteProcessMemory_8626 {
  strings:
    $key_8626 = { d1 54 [2] e3 76 [2] e5 43 [2] cb 43 [2] f4 5f }

  condition:
    any of them
}