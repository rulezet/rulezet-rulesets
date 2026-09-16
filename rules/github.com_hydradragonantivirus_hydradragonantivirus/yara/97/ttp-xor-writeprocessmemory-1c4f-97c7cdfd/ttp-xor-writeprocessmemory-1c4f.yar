rule TTP_XOR_WriteProcessMemory_1c4f {
  strings:
    $key_1c4f = { 4b 3d [2] 79 1f [2] 7f 2a [2] 51 2a [2] 6e 36 }

  condition:
    any of them
}