rule TTP_XOR_WriteProcessMemory_746d {
  strings:
    $key_746d = { 23 1f [2] 11 3d [2] 17 08 [2] 39 08 [2] 06 14 }

  condition:
    any of them
}