rule TTP_XOR_WriteProcessMemory_7041 {
  strings:
    $key_7041 = { 27 33 [2] 15 11 [2] 13 24 [2] 3d 24 [2] 02 38 }

  condition:
    any of them
}