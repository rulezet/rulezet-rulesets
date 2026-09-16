rule TTP_XOR_WriteProcessMemory_7043 {
  strings:
    $key_7043 = { 27 31 [2] 15 13 [2] 13 26 [2] 3d 26 [2] 02 3a }

  condition:
    any of them
}