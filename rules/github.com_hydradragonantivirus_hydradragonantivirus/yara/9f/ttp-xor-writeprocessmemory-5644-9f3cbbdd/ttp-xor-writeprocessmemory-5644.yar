rule TTP_XOR_WriteProcessMemory_5644 {
  strings:
    $key_5644 = { 01 36 [2] 33 14 [2] 35 21 [2] 1b 21 [2] 24 3d }

  condition:
    any of them
}