rule TTP_XOR_WriteProcessMemory_5053 {
  strings:
    $key_5053 = { 07 21 [2] 35 03 [2] 33 36 [2] 1d 36 [2] 22 2a }

  condition:
    any of them
}