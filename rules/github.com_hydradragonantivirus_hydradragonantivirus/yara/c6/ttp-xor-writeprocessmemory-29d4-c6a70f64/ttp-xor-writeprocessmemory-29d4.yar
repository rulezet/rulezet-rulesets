rule TTP_XOR_WriteProcessMemory_29d4 {
  strings:
    $key_29d4 = { 7e a6 [2] 4c 84 [2] 4a b1 [2] 64 b1 [2] 5b ad }

  condition:
    any of them
}