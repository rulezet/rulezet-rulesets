rule TTP_XOR_WriteProcessMemory_707a {
  strings:
    $key_707a = { 27 08 [2] 15 2a [2] 13 1f [2] 3d 1f [2] 02 03 }

  condition:
    any of them
}