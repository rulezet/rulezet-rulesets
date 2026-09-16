rule TTP_XOR_WriteProcessMemory_411e {
  strings:
    $key_411e = { 16 6c [2] 24 4e [2] 22 7b [2] 0c 7b [2] 33 67 }

  condition:
    any of them
}