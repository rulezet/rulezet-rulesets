rule TTP_XOR_WriteProcessMemory_39d4 {
  strings:
    $key_39d4 = { 6e a6 [2] 5c 84 [2] 5a b1 [2] 74 b1 [2] 4b ad }

  condition:
    any of them
}