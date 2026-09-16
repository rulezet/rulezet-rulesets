rule TTP_XOR_WriteProcessMemory_6a2d {
  strings:
    $key_6a2d = { 3d 5f [2] 0f 7d [2] 09 48 [2] 27 48 [2] 18 54 }

  condition:
    any of them
}