rule TTP_XOR_WriteProcessMemory_7f3d {
  strings:
    $key_7f3d = { 28 4f [2] 1a 6d [2] 1c 58 [2] 32 58 [2] 0d 44 }

  condition:
    any of them
}