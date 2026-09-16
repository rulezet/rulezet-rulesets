rule TTP_XOR_WriteProcessMemory_e9d6 {
  strings:
    $key_e9d6 = { be a4 [2] 8c 86 [2] 8a b3 [2] a4 b3 [2] 9b af }

  condition:
    any of them
}