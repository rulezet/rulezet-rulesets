rule TTP_XOR_WriteProcessMemory_366d {
  strings:
    $key_366d = { 61 1f [2] 53 3d [2] 55 08 [2] 7b 08 [2] 44 14 }

  condition:
    any of them
}