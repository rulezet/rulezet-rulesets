rule TTP_XOR_WriteProcessMemory_604f {
  strings:
    $key_604f = { 37 3d [2] 05 1f [2] 03 2a [2] 2d 2a [2] 12 36 }

  condition:
    any of them
}