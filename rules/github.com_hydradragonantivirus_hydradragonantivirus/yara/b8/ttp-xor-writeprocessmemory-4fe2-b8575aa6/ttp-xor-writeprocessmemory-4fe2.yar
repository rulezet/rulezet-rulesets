rule TTP_XOR_WriteProcessMemory_4fe2 {
  strings:
    $key_4fe2 = { 18 90 [2] 2a b2 [2] 2c 87 [2] 02 87 [2] 3d 9b }

  condition:
    any of them
}