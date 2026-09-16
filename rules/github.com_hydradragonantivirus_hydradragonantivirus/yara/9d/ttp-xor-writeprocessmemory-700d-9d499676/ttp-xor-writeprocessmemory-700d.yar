rule TTP_XOR_WriteProcessMemory_700d {
  strings:
    $key_700d = { 27 7f [2] 15 5d [2] 13 68 [2] 3d 68 [2] 02 74 }

  condition:
    any of them
}