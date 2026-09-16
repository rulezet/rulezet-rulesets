rule TTP_XOR_WriteProcessMemory_1f6d {
  strings:
    $key_1f6d = { 48 1f [2] 7a 3d [2] 7c 08 [2] 52 08 [2] 6d 14 }

  condition:
    any of them
}