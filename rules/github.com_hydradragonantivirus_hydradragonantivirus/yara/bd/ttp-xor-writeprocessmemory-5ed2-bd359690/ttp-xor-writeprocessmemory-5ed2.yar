rule TTP_XOR_WriteProcessMemory_5ed2 {
  strings:
    $key_5ed2 = { 09 a0 [2] 3b 82 [2] 3d b7 [2] 13 b7 [2] 2c ab }

  condition:
    any of them
}