rule TTP_XOR_WriteProcessMemory_4f67 {
  strings:
    $key_4f67 = { 18 15 [2] 2a 37 [2] 2c 02 [2] 02 02 [2] 3d 1e }

  condition:
    any of them
}