rule TTP_XOR_WriteProcessMemory_5554 {
  strings:
    $key_5554 = { 02 26 [2] 30 04 [2] 36 31 [2] 18 31 [2] 27 2d }

  condition:
    any of them
}