rule TTP_XOR_WriteProcessMemory_016d {
  strings:
    $key_016d = { 56 1f [2] 64 3d [2] 62 08 [2] 4c 08 [2] 73 14 }

  condition:
    any of them
}