rule TTP_XOR_WriteProcessMemory_7a2d {
  strings:
    $key_7a2d = { 2d 5f [2] 1f 7d [2] 19 48 [2] 37 48 [2] 08 54 }

  condition:
    any of them
}