rule TTP_XOR_WriteProcessMemory_2354 {
  strings:
    $key_2354 = { 74 26 [2] 46 04 [2] 40 31 [2] 6e 31 [2] 51 2d }

  condition:
    any of them
}