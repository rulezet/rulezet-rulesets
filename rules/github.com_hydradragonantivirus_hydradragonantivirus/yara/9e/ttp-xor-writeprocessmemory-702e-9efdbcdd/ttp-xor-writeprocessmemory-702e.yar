rule TTP_XOR_WriteProcessMemory_702e {
  strings:
    $key_702e = { 27 5c [2] 15 7e [2] 13 4b [2] 3d 4b [2] 02 57 }

  condition:
    any of them
}