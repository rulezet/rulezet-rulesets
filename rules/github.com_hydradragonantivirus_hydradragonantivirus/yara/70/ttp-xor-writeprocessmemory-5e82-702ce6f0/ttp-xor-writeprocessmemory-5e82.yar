rule TTP_XOR_WriteProcessMemory_5e82 {
  strings:
    $key_5e82 = { 09 f0 [2] 3b d2 [2] 3d e7 [2] 13 e7 [2] 2c fb }

  condition:
    any of them
}