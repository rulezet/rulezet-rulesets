rule TTP_XOR_WriteProcessMemory_5204 {
  strings:
    $key_5204 = { 05 76 [2] 37 54 [2] 31 61 [2] 1f 61 [2] 20 7d }

  condition:
    any of them
}