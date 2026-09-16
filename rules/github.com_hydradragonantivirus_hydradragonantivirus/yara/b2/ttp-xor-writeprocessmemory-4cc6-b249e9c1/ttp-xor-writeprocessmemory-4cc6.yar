rule TTP_XOR_WriteProcessMemory_4cc6 {
  strings:
    $key_4cc6 = { 1b b4 [2] 29 96 [2] 2f a3 [2] 01 a3 [2] 3e bf }

  condition:
    any of them
}