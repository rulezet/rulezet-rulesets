rule TTP_XOR_WriteProcessMemory_276d {
  strings:
    $key_276d = { 70 1f [2] 42 3d [2] 44 08 [2] 6a 08 [2] 55 14 }

  condition:
    any of them
}