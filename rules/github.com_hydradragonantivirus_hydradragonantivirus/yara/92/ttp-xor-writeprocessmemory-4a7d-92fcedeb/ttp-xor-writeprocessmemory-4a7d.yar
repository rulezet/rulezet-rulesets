rule TTP_XOR_WriteProcessMemory_4a7d {
  strings:
    $key_4a7d = { 1d 0f [2] 2f 2d [2] 29 18 [2] 07 18 [2] 38 04 }

  condition:
    any of them
}