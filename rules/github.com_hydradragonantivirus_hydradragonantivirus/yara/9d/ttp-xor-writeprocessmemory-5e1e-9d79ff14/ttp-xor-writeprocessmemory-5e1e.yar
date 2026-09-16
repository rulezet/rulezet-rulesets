rule TTP_XOR_WriteProcessMemory_5e1e {
  strings:
    $key_5e1e = { 09 6c [2] 3b 4e [2] 3d 7b [2] 13 7b [2] 2c 67 }

  condition:
    any of them
}