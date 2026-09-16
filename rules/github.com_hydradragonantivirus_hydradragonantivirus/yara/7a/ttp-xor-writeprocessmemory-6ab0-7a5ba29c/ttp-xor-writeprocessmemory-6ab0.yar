rule TTP_XOR_WriteProcessMemory_6ab0 {
  strings:
    $key_6ab0 = { 3d c2 [2] 0f e0 [2] 09 d5 [2] 27 d5 [2] 18 c9 }

  condition:
    any of them
}