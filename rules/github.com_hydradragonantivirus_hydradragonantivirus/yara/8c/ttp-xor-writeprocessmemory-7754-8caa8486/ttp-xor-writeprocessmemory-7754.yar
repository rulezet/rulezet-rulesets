rule TTP_XOR_WriteProcessMemory_7754 {
  strings:
    $key_7754 = { 20 26 [2] 12 04 [2] 14 31 [2] 3a 31 [2] 05 2d }

  condition:
    any of them
}