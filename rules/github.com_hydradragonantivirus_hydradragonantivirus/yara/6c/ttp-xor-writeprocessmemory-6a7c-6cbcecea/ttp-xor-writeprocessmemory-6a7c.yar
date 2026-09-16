rule TTP_XOR_WriteProcessMemory_6a7c {
  strings:
    $key_6a7c = { 3d 0e [2] 0f 2c [2] 09 19 [2] 27 19 [2] 18 05 }

  condition:
    any of them
}