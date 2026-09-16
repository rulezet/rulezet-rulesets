rule TTP_XOR_WriteProcessMemory_4f0e {
  strings:
    $key_4f0e = { 18 7c [2] 2a 5e [2] 2c 6b [2] 02 6b [2] 3d 77 }

  condition:
    any of them
}