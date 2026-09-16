rule TTP_XOR_WriteProcessMemory_4571 {
  strings:
    $key_4571 = { 12 03 [2] 20 21 [2] 26 14 [2] 08 14 [2] 37 08 }

  condition:
    any of them
}