rule TTP_XOR_WriteProcessMemory_346d {
  strings:
    $key_346d = { 63 1f [2] 51 3d [2] 57 08 [2] 79 08 [2] 46 14 }

  condition:
    any of them
}