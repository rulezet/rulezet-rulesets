rule TTP_XOR_WriteProcessMemory_3d48 {
  strings:
    $key_3d48 = { 6a 3a [2] 58 18 [2] 5e 2d [2] 70 2d [2] 4f 31 }

  condition:
    any of them
}