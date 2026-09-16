rule TTP_XOR_WriteProcessMemory_52f6 {
  strings:
    $key_52f6 = { 05 84 [2] 37 a6 [2] 31 93 [2] 1f 93 [2] 20 8f }

  condition:
    any of them
}