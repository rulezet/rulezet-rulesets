rule TTP_XOR_WriteProcessMemory_3d78 {
  strings:
    $key_3d78 = { 6a 0a [2] 58 28 [2] 5e 1d [2] 70 1d [2] 4f 01 }

  condition:
    any of them
}