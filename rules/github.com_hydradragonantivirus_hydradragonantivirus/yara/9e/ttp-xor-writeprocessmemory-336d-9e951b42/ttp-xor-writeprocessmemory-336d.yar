rule TTP_XOR_WriteProcessMemory_336d {
  strings:
    $key_336d = { 64 1f [2] 56 3d [2] 50 08 [2] 7e 08 [2] 41 14 }

  condition:
    any of them
}