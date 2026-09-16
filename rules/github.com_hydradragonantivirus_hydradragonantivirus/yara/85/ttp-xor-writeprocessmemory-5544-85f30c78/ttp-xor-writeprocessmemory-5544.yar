rule TTP_XOR_WriteProcessMemory_5544 {
  strings:
    $key_5544 = { 02 36 [2] 30 14 [2] 36 21 [2] 18 21 [2] 27 3d }

  condition:
    any of them
}