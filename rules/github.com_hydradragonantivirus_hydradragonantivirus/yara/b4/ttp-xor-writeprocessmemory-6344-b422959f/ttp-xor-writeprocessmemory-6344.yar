rule TTP_XOR_WriteProcessMemory_6344 {
  strings:
    $key_6344 = { 34 36 [2] 06 14 [2] 00 21 [2] 2e 21 [2] 11 3d }

  condition:
    any of them
}