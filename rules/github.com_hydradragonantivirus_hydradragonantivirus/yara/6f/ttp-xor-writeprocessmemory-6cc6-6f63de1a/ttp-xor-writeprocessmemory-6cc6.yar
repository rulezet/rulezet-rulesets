rule TTP_XOR_WriteProcessMemory_6cc6 {
  strings:
    $key_6cc6 = { 3b b4 [2] 09 96 [2] 0f a3 [2] 21 a3 [2] 1e bf }

  condition:
    any of them
}