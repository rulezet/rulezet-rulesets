rule TTP_XOR_WriteProcessMemory_1b4f {
  strings:
    $key_1b4f = { 4c 3d [2] 7e 1f [2] 78 2a [2] 56 2a [2] 69 36 }

  condition:
    any of them
}