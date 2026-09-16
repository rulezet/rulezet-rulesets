rule TTP_XOR_WriteProcessMemory_5e64 {
  strings:
    $key_5e64 = { 09 16 [2] 3b 34 [2] 3d 01 [2] 13 01 [2] 2c 1d }

  condition:
    any of them
}