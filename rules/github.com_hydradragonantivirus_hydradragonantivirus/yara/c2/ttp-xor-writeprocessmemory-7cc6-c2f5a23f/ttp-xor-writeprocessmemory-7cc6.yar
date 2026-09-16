rule TTP_XOR_WriteProcessMemory_7cc6 {
  strings:
    $key_7cc6 = { 2b b4 [2] 19 96 [2] 1f a3 [2] 31 a3 [2] 0e bf }

  condition:
    any of them
}