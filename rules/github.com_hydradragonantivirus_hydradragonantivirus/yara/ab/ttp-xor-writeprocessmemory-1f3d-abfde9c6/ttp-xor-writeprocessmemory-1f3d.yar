rule TTP_XOR_WriteProcessMemory_1f3d {
  strings:
    $key_1f3d = { 48 4f [2] 7a 6d [2] 7c 58 [2] 52 58 [2] 6d 44 }

  condition:
    any of them
}