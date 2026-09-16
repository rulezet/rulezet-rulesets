rule TTP_XOR_WriteProcessMemory_256d {
  strings:
    $key_256d = { 72 1f [2] 40 3d [2] 46 08 [2] 68 08 [2] 57 14 }

  condition:
    any of them
}