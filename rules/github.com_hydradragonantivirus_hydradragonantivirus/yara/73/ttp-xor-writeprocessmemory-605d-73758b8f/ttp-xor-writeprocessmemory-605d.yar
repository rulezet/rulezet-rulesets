rule TTP_XOR_WriteProcessMemory_605d {
  strings:
    $key_605d = { 37 2f [2] 05 0d [2] 03 38 [2] 2d 38 [2] 12 24 }

  condition:
    any of them
}