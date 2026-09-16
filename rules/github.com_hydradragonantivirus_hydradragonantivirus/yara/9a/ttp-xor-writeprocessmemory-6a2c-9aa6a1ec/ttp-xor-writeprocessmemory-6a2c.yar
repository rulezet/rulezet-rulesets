rule TTP_XOR_WriteProcessMemory_6a2c {
  strings:
    $key_6a2c = { 3d 5e [2] 0f 7c [2] 09 49 [2] 27 49 [2] 18 55 }

  condition:
    any of them
}