rule TTP_XOR_WriteProcessMemory_2a6d {
  strings:
    $key_2a6d = { 7d 1f [2] 4f 3d [2] 49 08 [2] 67 08 [2] 58 14 }

  condition:
    any of them
}