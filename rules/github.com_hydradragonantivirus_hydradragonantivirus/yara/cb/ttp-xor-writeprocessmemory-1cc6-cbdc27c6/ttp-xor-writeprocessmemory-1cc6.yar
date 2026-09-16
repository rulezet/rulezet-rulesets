rule TTP_XOR_WriteProcessMemory_1cc6 {
  strings:
    $key_1cc6 = { 4b b4 [2] 79 96 [2] 7f a3 [2] 51 a3 [2] 6e bf }

  condition:
    any of them
}