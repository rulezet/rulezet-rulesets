rule TTP_XOR_WriteProcessMemory_2554 {
  strings:
    $key_2554 = { 72 26 [2] 40 04 [2] 46 31 [2] 68 31 [2] 57 2d }

  condition:
    any of them
}