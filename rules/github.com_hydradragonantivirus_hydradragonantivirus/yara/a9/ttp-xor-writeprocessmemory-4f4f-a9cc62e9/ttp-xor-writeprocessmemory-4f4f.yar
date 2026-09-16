rule TTP_XOR_WriteProcessMemory_4f4f {
  strings:
    $key_4f4f = { 18 3d [2] 2a 1f [2] 2c 2a [2] 02 2a [2] 3d 36 }

  condition:
    any of them
}