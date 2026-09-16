rule TTP_XOR_WriteProcessMemory_436d {
  strings:
    $key_436d = { 14 1f [2] 26 3d [2] 20 08 [2] 0e 08 [2] 31 14 }

  condition:
    any of them
}