rule TTP_XOR_WriteProcessMemory_7079 {
  strings:
    $key_7079 = { 27 0b [2] 15 29 [2] 13 1c [2] 3d 1c [2] 02 00 }

  condition:
    any of them
}