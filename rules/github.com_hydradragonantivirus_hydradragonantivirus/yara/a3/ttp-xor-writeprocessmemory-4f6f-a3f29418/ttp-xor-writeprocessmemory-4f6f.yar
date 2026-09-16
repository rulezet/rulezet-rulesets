rule TTP_XOR_WriteProcessMemory_4f6f {
  strings:
    $key_4f6f = { 18 1d [2] 2a 3f [2] 2c 0a [2] 02 0a [2] 3d 16 }

  condition:
    any of them
}