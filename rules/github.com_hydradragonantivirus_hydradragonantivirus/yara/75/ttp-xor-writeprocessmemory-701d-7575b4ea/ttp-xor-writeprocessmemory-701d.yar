rule TTP_XOR_WriteProcessMemory_701d {
  strings:
    $key_701d = { 27 6f [2] 15 4d [2] 13 78 [2] 3d 78 [2] 02 64 }

  condition:
    any of them
}