rule TTP_XOR_WriteProcessMemory_700c {
  strings:
    $key_700c = { 27 7e [2] 15 5c [2] 13 69 [2] 3d 69 [2] 02 75 }

  condition:
    any of them
}