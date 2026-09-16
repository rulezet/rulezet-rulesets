rule TTP_XOR_WriteProcessMemory_5e52 {
  strings:
    $key_5e52 = { 09 20 [2] 3b 02 [2] 3d 37 [2] 13 37 [2] 2c 2b }

  condition:
    any of them
}