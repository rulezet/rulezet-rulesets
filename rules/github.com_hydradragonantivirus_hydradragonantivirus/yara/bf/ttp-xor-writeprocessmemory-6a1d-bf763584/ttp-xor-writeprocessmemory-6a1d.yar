rule TTP_XOR_WriteProcessMemory_6a1d {
  strings:
    $key_6a1d = { 3d 6f [2] 0f 4d [2] 09 78 [2] 27 78 [2] 18 64 }

  condition:
    any of them
}