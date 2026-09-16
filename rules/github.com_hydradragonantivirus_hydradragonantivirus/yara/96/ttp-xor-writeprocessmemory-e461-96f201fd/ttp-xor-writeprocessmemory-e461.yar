rule TTP_XOR_WriteProcessMemory_e461 {
  strings:
    $key_e461 = { b3 13 [2] 81 31 [2] 87 04 [2] a9 04 [2] 96 18 }

  condition:
    any of them
}