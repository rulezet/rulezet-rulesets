rule TTP_XOR_WriteProcessMemory_52e6 {
  strings:
    $key_52e6 = { 05 94 [2] 37 b6 [2] 31 83 [2] 1f 83 [2] 20 9f }

  condition:
    any of them
}