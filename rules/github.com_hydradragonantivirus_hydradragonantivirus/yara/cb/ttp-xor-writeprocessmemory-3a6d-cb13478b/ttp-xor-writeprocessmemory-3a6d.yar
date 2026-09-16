rule TTP_XOR_WriteProcessMemory_3a6d {
  strings:
    $key_3a6d = { 6d 1f [2] 5f 3d [2] 59 08 [2] 77 08 [2] 48 14 }

  condition:
    any of them
}