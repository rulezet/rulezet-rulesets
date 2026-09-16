rule TTP_XOR_WriteProcessMemory_4f2f {
  strings:
    $key_4f2f = { 18 5d [2] 2a 7f [2] 2c 4a [2] 02 4a [2] 3d 56 }

  condition:
    any of them
}