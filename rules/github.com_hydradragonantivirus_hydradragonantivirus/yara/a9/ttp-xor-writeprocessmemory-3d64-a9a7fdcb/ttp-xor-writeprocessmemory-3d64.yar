rule TTP_XOR_WriteProcessMemory_3d64 {
  strings:
    $key_3d64 = { 6a 16 [2] 58 34 [2] 5e 01 [2] 70 01 [2] 4f 1d }

  condition:
    any of them
}