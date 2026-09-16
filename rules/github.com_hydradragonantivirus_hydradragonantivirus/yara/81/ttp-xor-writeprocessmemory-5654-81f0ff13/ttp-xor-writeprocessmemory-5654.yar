rule TTP_XOR_WriteProcessMemory_5654 {
  strings:
    $key_5654 = { 01 26 [2] 33 04 [2] 35 31 [2] 1b 31 [2] 24 2d }

  condition:
    any of them
}