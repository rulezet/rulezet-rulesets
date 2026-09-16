rule TTP_XOR_WriteProcessMemory_6544 {
  strings:
    $key_6544 = { 32 36 [2] 00 14 [2] 06 21 [2] 28 21 [2] 17 3d }

  condition:
    any of them
}