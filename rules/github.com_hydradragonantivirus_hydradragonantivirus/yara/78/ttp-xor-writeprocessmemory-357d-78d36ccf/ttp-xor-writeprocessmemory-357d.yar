rule TTP_XOR_WriteProcessMemory_357d {
  strings:
    $key_357d = { 62 0f [2] 50 2d [2] 56 18 [2] 78 18 [2] 47 04 }

  condition:
    any of them
}