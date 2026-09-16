rule TTP_XOR_WriteProcessMemory_6604 {
  strings:
    $key_6604 = { 31 76 [2] 03 54 [2] 05 61 [2] 2b 61 [2] 14 7d }

  condition:
    any of them
}