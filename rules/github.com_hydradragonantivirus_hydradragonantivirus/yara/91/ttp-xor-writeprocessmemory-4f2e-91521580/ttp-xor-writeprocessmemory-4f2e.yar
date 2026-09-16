rule TTP_XOR_WriteProcessMemory_4f2e {
  strings:
    $key_4f2e = { 18 5c [2] 2a 7e [2] 2c 4b [2] 02 4b [2] 3d 57 }

  condition:
    any of them
}