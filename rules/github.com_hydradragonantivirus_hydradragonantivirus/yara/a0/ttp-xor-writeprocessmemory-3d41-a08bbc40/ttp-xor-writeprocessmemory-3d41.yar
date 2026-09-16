rule TTP_XOR_WriteProcessMemory_3d41 {
  strings:
    $key_3d41 = { 6a 33 [2] 58 11 [2] 5e 24 [2] 70 24 [2] 4f 38 }

  condition:
    any of them
}