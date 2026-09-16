rule TTP_XOR_WriteProcessMemory_4f6e {
  strings:
    $key_4f6e = { 18 1c [2] 2a 3e [2] 2c 0b [2] 02 0b [2] 3d 17 }

  condition:
    any of them
}