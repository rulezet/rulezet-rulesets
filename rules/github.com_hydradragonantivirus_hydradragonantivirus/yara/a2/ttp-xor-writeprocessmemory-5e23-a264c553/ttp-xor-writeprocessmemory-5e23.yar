rule TTP_XOR_WriteProcessMemory_5e23 {
  strings:
    $key_5e23 = { 09 51 [2] 3b 73 [2] 3d 46 [2] 13 46 [2] 2c 5a }

  condition:
    any of them
}