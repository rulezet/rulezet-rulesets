rule TTP_XOR_WriteProcessMemory_4f30 {
  strings:
    $key_4f30 = { 18 42 [2] 2a 60 [2] 2c 55 [2] 02 55 [2] 3d 49 }

  condition:
    any of them
}