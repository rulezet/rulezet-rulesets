rule TTP_XOR_WriteProcessMemory_2f4f {
  strings:
    $key_2f4f = { 78 3d [2] 4a 1f [2] 4c 2a [2] 62 2a [2] 5d 36 }

  condition:
    any of them
}