rule TTP_XOR_WriteProcessMemory_4f14 {
  strings:
    $key_4f14 = { 18 66 [2] 2a 44 [2] 2c 71 [2] 02 71 [2] 3d 6d }

  condition:
    any of them
}