rule TTP_XOR_WriteProcessMemory_3c6d {
  strings:
    $key_3c6d = { 6b 1f [2] 59 3d [2] 5f 08 [2] 71 08 [2] 4e 14 }

  condition:
    any of them
}