rule TTP_XOR_WriteProcessMemory_5154 {
  strings:
    $key_5154 = { 06 26 [2] 34 04 [2] 32 31 [2] 1c 31 [2] 23 2d }

  condition:
    any of them
}