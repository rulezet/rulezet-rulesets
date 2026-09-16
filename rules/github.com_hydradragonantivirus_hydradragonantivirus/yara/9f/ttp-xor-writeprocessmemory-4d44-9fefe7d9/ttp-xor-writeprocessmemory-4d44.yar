rule TTP_XOR_WriteProcessMemory_4d44 {
  strings:
    $key_4d44 = { 1a 36 [2] 28 14 [2] 2e 21 [2] 00 21 [2] 3f 3d }

  condition:
    any of them
}