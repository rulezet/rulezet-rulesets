rule TTP_XOR_WriteProcessMemory_5b6d {
  strings:
    $key_5b6d = { 0c 1f [2] 3e 3d [2] 38 08 [2] 16 08 [2] 29 14 }

  condition:
    any of them
}