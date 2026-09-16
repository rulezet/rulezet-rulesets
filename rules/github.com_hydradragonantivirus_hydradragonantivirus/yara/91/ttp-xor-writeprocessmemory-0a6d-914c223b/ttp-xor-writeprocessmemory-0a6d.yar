rule TTP_XOR_WriteProcessMemory_0a6d {
  strings:
    $key_0a6d = { 5d 1f [2] 6f 3d [2] 69 08 [2] 47 08 [2] 78 14 }

  condition:
    any of them
}