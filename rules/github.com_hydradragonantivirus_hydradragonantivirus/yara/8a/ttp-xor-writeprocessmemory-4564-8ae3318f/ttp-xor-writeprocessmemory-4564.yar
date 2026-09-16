rule TTP_XOR_WriteProcessMemory_4564 {
  strings:
    $key_4564 = { 12 16 [2] 20 34 [2] 26 01 [2] 08 01 [2] 37 1d }

  condition:
    any of them
}