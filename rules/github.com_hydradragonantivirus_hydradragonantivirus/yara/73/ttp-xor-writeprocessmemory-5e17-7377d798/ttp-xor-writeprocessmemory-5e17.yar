rule TTP_XOR_WriteProcessMemory_5e17 {
  strings:
    $key_5e17 = { 09 65 [2] 3b 47 [2] 3d 72 [2] 13 72 [2] 2c 6e }

  condition:
    any of them
}