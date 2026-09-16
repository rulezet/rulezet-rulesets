rule TTP_XOR_WriteProcessMemory_3d7c {
  strings:
    $key_3d7c = { 6a 0e [2] 58 2c [2] 5e 19 [2] 70 19 [2] 4f 05 }

  condition:
    any of them
}