rule TTP_XOR_WriteProcessMemory_701e {
  strings:
    $key_701e = { 27 6c [2] 15 4e [2] 13 7b [2] 3d 7b [2] 02 67 }

  condition:
    any of them
}