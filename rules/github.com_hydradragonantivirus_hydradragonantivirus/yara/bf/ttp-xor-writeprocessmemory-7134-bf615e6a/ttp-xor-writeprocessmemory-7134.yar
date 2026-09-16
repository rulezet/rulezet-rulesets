rule TTP_XOR_WriteProcessMemory_7134 {
  strings:
    $key_7134 = { 26 46 [2] 14 64 [2] 12 51 [2] 3c 51 [2] 03 4d }

  condition:
    any of them
}