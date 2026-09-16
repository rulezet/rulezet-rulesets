rule TTP_XOR_WriteProcessMemory_4ffb {
  strings:
    $key_4ffb = { 18 89 [2] 2a ab [2] 2c 9e [2] 02 9e [2] 3d 82 }

  condition:
    any of them
}