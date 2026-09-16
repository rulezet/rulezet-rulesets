rule TTP_XOR_WriteProcessMemory_4354 {
  strings:
    $key_4354 = { 14 26 [2] 26 04 [2] 20 31 [2] 0e 31 [2] 31 2d }

  condition:
    any of them
}