rule TTP_XOR_WriteProcessMemory_707f {
  strings:
    $key_707f = { 27 0d [2] 15 2f [2] 13 1a [2] 3d 1a [2] 02 06 }

  condition:
    any of them
}