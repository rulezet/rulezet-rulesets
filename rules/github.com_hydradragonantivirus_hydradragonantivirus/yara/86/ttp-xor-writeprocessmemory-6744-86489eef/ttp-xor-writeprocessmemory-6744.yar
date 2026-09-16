rule TTP_XOR_WriteProcessMemory_6744 {
  strings:
    $key_6744 = { 30 36 [2] 02 14 [2] 04 21 [2] 2a 21 [2] 15 3d }

  condition:
    any of them
}