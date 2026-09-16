rule TTP_XOR_WriteProcessMemory_7a5d {
  strings:
    $key_7a5d = { 2d 2f [2] 1f 0d [2] 19 38 [2] 37 38 [2] 08 24 }

  condition:
    any of them
}