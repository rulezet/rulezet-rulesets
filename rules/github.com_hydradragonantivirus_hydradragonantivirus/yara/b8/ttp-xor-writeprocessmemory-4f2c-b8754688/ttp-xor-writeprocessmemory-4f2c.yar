rule TTP_XOR_WriteProcessMemory_4f2c {
  strings:
    $key_4f2c = { 18 5e [2] 2a 7c [2] 2c 49 [2] 02 49 [2] 3d 55 }

  condition:
    any of them
}