rule TTP_XOR_WriteProcessMemory_703e {
  strings:
    $key_703e = { 27 4c [2] 15 6e [2] 13 5b [2] 3d 5b [2] 02 47 }

  condition:
    any of them
}