rule TTP_XOR_WriteProcessMemory_23bb {
  strings:
    $key_23bb = { 74 c9 [2] 46 eb [2] 40 de [2] 6e de [2] 51 c2 }

  condition:
    any of them
}