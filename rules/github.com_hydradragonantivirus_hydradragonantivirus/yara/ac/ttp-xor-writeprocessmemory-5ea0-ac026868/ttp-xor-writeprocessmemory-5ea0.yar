rule TTP_XOR_WriteProcessMemory_5ea0 {
  strings:
    $key_5ea0 = { 09 d2 [2] 3b f0 [2] 3d c5 [2] 13 c5 [2] 2c d9 }

  condition:
    any of them
}