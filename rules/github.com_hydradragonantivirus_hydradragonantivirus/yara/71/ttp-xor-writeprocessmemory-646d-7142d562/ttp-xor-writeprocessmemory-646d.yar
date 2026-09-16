rule TTP_XOR_WriteProcessMemory_646d {
  strings:
    $key_646d = { 33 1f [2] 01 3d [2] 07 08 [2] 29 08 [2] 16 14 }

  condition:
    any of them
}