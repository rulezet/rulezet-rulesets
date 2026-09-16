rule TTP_XOR_WriteProcessMemory_5226 {
  strings:
    $key_5226 = { 05 54 [2] 37 76 [2] 31 43 [2] 1f 43 [2] 20 5f }

  condition:
    any of them
}