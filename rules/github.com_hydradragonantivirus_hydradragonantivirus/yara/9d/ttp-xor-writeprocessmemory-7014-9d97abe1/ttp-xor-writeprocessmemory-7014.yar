rule TTP_XOR_WriteProcessMemory_7014 {
  strings:
    $key_7014 = { 27 66 [2] 15 44 [2] 13 71 [2] 3d 71 [2] 02 6d }

  condition:
    any of them
}