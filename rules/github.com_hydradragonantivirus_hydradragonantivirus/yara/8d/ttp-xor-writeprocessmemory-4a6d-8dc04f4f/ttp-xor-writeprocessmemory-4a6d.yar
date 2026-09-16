rule TTP_XOR_WriteProcessMemory_4a6d {
  strings:
    $key_4a6d = { 1d 1f [2] 2f 3d [2] 29 08 [2] 07 08 [2] 38 14 }

  condition:
    any of them
}