rule TTP_XOR_WriteProcessMemory_766d {
  strings:
    $key_766d = { 21 1f [2] 13 3d [2] 15 08 [2] 3b 08 [2] 04 14 }

  condition:
    any of them
}