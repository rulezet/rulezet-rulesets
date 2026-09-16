rule TTP_XOR_WriteProcessMemory_5e67 {
  strings:
    $key_5e67 = { 09 15 [2] 3b 37 [2] 3d 02 [2] 13 02 [2] 2c 1e }

  condition:
    any of them
}