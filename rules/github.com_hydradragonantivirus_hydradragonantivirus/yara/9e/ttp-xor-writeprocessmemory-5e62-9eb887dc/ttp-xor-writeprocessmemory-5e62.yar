rule TTP_XOR_WriteProcessMemory_5e62 {
  strings:
    $key_5e62 = { 09 10 [2] 3b 32 [2] 3d 07 [2] 13 07 [2] 2c 1b }

  condition:
    any of them
}