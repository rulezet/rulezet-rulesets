rule TTP_XOR_WriteProcessMemory_5cc6 {
  strings:
    $key_5cc6 = { 0b b4 [2] 39 96 [2] 3f a3 [2] 11 a3 [2] 2e bf }

  condition:
    any of them
}