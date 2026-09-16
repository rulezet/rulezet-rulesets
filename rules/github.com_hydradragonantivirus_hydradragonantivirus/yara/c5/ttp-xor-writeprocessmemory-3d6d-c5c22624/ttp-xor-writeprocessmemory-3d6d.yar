rule TTP_XOR_WriteProcessMemory_3d6d {
  strings:
    $key_3d6d = { 6a 1f [2] 58 3d [2] 5e 08 [2] 70 08 [2] 4f 14 }

  condition:
    any of them
}