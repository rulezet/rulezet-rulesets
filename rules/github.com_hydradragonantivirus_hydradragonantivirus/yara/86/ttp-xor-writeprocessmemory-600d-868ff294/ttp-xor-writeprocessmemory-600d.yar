rule TTP_XOR_WriteProcessMemory_600d {
  strings:
    $key_600d = { 37 7f [2] 05 5d [2] 03 68 [2] 2d 68 [2] 12 74 }

  condition:
    any of them
}