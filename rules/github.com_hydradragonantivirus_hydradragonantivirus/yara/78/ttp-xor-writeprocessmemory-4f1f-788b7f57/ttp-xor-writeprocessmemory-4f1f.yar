rule TTP_XOR_WriteProcessMemory_4f1f {
  strings:
    $key_4f1f = { 18 6d [2] 2a 4f [2] 2c 7a [2] 02 7a [2] 3d 66 }

  condition:
    any of them
}