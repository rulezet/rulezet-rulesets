rule TTP_XOR_WriteProcessMemory_4f4e {
  strings:
    $key_4f4e = { 18 3c [2] 2a 1e [2] 2c 2b [2] 02 2b [2] 3d 37 }

  condition:
    any of them
}