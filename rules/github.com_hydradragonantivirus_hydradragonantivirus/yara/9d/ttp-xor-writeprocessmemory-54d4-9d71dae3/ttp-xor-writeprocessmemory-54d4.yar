rule TTP_XOR_WriteProcessMemory_54d4 {
  strings:
    $key_54d4 = { 03 a6 [2] 31 84 [2] 37 b1 [2] 19 b1 [2] 26 ad }

  condition:
    any of them
}