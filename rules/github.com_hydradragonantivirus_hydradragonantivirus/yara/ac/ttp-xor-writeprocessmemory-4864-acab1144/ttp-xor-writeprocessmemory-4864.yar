rule TTP_XOR_WriteProcessMemory_4864 {
  strings:
    $key_4864 = { 1f 16 [2] 2d 34 [2] 2b 01 [2] 05 01 [2] 3a 1d }

  condition:
    any of them
}