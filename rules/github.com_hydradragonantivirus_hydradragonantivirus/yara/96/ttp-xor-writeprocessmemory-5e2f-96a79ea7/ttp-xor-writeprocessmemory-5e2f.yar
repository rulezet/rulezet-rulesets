rule TTP_XOR_WriteProcessMemory_5e2f {
  strings:
    $key_5e2f = { 09 5d [2] 3b 7f [2] 3d 4a [2] 13 4a [2] 2c 56 }

  condition:
    any of them
}