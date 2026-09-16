rule TTP_XOR_WriteProcessMemory_6f6d {
  strings:
    $key_6f6d = { 38 1f [2] 0a 3d [2] 0c 08 [2] 22 08 [2] 1d 14 }

  condition:
    any of them
}