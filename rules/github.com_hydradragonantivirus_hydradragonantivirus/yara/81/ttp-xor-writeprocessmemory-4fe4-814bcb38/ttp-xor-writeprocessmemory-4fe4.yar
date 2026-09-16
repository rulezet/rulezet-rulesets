rule TTP_XOR_WriteProcessMemory_4fe4 {
  strings:
    $key_4fe4 = { 18 96 [2] 2a b4 [2] 2c 81 [2] 02 81 [2] 3d 9d }

  condition:
    any of them
}