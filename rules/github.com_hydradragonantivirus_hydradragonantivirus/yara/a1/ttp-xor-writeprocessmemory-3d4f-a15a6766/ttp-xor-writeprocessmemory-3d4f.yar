rule TTP_XOR_WriteProcessMemory_3d4f {
  strings:
    $key_3d4f = { 6a 3d [2] 58 1f [2] 5e 2a [2] 70 2a [2] 4f 36 }

  condition:
    any of them
}