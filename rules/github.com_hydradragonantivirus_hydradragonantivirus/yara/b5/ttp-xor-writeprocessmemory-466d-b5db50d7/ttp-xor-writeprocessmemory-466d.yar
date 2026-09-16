rule TTP_XOR_WriteProcessMemory_466d {
  strings:
    $key_466d = { 11 1f [2] 23 3d [2] 25 08 [2] 0b 08 [2] 34 14 }

  condition:
    any of them
}