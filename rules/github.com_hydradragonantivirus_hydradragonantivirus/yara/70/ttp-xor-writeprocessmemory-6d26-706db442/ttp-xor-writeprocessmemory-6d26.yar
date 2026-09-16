rule TTP_XOR_WriteProcessMemory_6d26 {
  strings:
    $key_6d26 = { 3a 54 [2] 08 76 [2] 0e 43 [2] 20 43 [2] 1f 5f }

  condition:
    any of them
}