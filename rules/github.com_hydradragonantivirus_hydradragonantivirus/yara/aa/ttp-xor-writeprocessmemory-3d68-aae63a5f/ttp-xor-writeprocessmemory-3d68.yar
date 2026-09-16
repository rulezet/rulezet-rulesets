rule TTP_XOR_WriteProcessMemory_3d68 {
  strings:
    $key_3d68 = { 6a 1a [2] 58 38 [2] 5e 0d [2] 70 0d [2] 4f 11 }

  condition:
    any of them
}