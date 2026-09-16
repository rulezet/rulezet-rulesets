rule TTP_XOR_WriteProcessMemory_5e7c {
  strings:
    $key_5e7c = { 09 0e [2] 3b 2c [2] 3d 19 [2] 13 19 [2] 2c 05 }

  condition:
    any of them
}