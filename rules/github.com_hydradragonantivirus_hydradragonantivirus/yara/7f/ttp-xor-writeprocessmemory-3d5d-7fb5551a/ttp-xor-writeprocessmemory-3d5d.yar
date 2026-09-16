rule TTP_XOR_WriteProcessMemory_3d5d {
  strings:
    $key_3d5d = { 6a 2f [2] 58 0d [2] 5e 38 [2] 70 38 [2] 4f 24 }

  condition:
    any of them
}