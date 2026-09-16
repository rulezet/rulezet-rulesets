rule TTP_XOR_WriteProcessMemory_19d4 {
  strings:
    $key_19d4 = { 4e a6 [2] 7c 84 [2] 7a b1 [2] 54 b1 [2] 6b ad }

  condition:
    any of them
}