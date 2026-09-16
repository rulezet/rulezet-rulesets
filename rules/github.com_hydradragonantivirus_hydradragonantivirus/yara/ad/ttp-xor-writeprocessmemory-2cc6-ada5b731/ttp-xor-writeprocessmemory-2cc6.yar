rule TTP_XOR_WriteProcessMemory_2cc6 {
  strings:
    $key_2cc6 = { 7b b4 [2] 49 96 [2] 4f a3 [2] 61 a3 [2] 5e bf }

  condition:
    any of them
}