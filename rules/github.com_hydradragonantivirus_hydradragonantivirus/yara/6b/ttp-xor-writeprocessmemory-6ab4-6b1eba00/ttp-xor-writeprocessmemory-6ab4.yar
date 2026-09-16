rule TTP_XOR_WriteProcessMemory_6ab4 {
  strings:
    $key_6ab4 = { 3d c6 [2] 0f e4 [2] 09 d1 [2] 27 d1 [2] 18 cd }

  condition:
    any of them
}