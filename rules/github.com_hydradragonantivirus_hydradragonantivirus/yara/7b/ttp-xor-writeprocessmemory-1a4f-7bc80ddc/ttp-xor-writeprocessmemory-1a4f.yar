rule TTP_XOR_WriteProcessMemory_1a4f {
  strings:
    $key_1a4f = { 4d 3d [2] 7f 1f [2] 79 2a [2] 57 2a [2] 68 36 }

  condition:
    any of them
}