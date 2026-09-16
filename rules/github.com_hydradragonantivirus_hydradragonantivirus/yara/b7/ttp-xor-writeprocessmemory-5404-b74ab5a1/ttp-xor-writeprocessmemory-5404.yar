rule TTP_XOR_WriteProcessMemory_5404 {
  strings:
    $key_5404 = { 03 76 [2] 31 54 [2] 37 61 [2] 19 61 [2] 26 7d }

  condition:
    any of them
}