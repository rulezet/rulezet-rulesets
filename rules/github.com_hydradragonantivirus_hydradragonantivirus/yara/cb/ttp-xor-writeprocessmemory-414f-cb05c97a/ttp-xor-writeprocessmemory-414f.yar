rule TTP_XOR_WriteProcessMemory_414f {
  strings:
    $key_414f = { 16 3d [2] 24 1f [2] 22 2a [2] 0c 2a [2] 33 36 }

  condition:
    any of them
}