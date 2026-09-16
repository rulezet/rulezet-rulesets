rule TTP_XOR_WriteProcessMemory_70ca {
  strings:
    $key_70ca = { 27 b8 [2] 15 9a [2] 13 af [2] 3d af [2] 02 b3 }

  condition:
    any of them
}