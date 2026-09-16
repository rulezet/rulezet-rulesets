rule TTP_XOR_WriteProcessMemory_6d6d {
  strings:
    $key_6d6d = { 3a 1f [2] 08 3d [2] 0e 08 [2] 20 08 [2] 1f 14 }

  condition:
    any of them
}