rule TTP_XOR_WriteProcessMemory_7b44 {
  strings:
    $key_7b44 = { 2c 36 [2] 1e 14 [2] 18 21 [2] 36 21 [2] 09 3d }

  condition:
    any of them
}