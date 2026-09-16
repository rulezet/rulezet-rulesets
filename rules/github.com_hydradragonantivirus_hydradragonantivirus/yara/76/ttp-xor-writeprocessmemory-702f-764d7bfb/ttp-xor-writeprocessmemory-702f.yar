rule TTP_XOR_WriteProcessMemory_702f {
  strings:
    $key_702f = { 27 5d [2] 15 7f [2] 13 4a [2] 3d 4a [2] 02 56 }

  condition:
    any of them
}