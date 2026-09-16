rule TTP_XOR_WriteProcessMemory_52d4 {
  strings:
    $key_52d4 = { 05 a6 [2] 37 84 [2] 31 b1 [2] 1f b1 [2] 20 ad }

  condition:
    any of them
}