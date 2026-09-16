rule TTP_XOR_WriteProcessMemory_4f17 {
  strings:
    $key_4f17 = { 18 65 [2] 2a 47 [2] 2c 72 [2] 02 72 [2] 3d 6e }

  condition:
    any of them
}