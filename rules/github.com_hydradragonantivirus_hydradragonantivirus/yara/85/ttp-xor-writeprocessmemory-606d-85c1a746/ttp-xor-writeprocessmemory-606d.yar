rule TTP_XOR_WriteProcessMemory_606d {
  strings:
    $key_606d = { 37 1f [2] 05 3d [2] 03 08 [2] 2d 08 [2] 12 14 }

  condition:
    any of them
}