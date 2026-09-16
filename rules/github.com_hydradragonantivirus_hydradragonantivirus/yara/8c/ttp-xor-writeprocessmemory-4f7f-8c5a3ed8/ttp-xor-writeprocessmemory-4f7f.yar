rule TTP_XOR_WriteProcessMemory_4f7f {
  strings:
    $key_4f7f = { 18 0d [2] 2a 2f [2] 2c 1a [2] 02 1a [2] 3d 06 }

  condition:
    any of them
}