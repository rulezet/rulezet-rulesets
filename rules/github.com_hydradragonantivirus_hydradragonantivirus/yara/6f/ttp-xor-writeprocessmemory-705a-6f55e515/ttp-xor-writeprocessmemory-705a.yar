rule TTP_XOR_WriteProcessMemory_705a {
  strings:
    $key_705a = { 27 28 [2] 15 0a [2] 13 3f [2] 3d 3f [2] 02 23 }

  condition:
    any of them
}