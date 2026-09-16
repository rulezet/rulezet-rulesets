rule TTP_XOR_WriteProcessMemory_415f {
  strings:
    $key_415f = { 16 2d [2] 24 0f [2] 22 3a [2] 0c 3a [2] 33 26 }

  condition:
    any of them
}