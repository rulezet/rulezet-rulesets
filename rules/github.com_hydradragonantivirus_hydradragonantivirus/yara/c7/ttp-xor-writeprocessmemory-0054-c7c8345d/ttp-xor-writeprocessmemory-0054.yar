rule TTP_XOR_WriteProcessMemory_0054 {
  strings:
    $key_0054 = { 57 26 [2] 65 04 [2] 63 31 [2] 4d 31 [2] 72 2d }

  condition:
    any of them
}