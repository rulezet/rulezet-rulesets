rule TTP_XOR_WriteProcessMemory_776d {
  strings:
    $key_776d = { 20 1f [2] 12 3d [2] 14 08 [2] 3a 08 [2] 05 14 }

  condition:
    any of them
}