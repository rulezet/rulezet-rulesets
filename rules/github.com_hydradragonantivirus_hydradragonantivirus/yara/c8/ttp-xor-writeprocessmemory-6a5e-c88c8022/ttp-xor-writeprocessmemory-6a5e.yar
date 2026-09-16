rule TTP_XOR_WriteProcessMemory_6a5e {
  strings:
    $key_6a5e = { 3d 2c [2] 0f 0e [2] 09 3b [2] 27 3b [2] 18 27 }

  condition:
    any of them
}