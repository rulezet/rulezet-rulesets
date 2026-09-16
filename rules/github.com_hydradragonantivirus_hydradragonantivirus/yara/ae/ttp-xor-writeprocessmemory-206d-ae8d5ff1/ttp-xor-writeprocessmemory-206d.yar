rule TTP_XOR_WriteProcessMemory_206d {
  strings:
    $key_206d = { 77 1f [2] 45 3d [2] 43 08 [2] 6d 08 [2] 52 14 }

  condition:
    any of them
}