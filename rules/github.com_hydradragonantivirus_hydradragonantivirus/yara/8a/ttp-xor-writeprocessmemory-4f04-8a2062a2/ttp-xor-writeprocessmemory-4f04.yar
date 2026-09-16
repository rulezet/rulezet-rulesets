rule TTP_XOR_WriteProcessMemory_4f04 {
  strings:
    $key_4f04 = { 18 76 [2] 2a 54 [2] 2c 61 [2] 02 61 [2] 3d 7d }

  condition:
    any of them
}