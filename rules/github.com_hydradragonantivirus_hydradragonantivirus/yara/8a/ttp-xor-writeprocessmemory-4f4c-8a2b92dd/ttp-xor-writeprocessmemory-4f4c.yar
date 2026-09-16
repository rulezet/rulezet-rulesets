rule TTP_XOR_WriteProcessMemory_4f4c {
  strings:
    $key_4f4c = { 18 3e [2] 2a 1c [2] 2c 29 [2] 02 29 [2] 3d 35 }

  condition:
    any of them
}