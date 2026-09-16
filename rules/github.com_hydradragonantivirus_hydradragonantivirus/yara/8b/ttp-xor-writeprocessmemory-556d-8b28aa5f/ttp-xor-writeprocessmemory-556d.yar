rule TTP_XOR_WriteProcessMemory_556d {
  strings:
    $key_556d = { 02 1f [2] 30 3d [2] 36 08 [2] 18 08 [2] 27 14 }

  condition:
    any of them
}