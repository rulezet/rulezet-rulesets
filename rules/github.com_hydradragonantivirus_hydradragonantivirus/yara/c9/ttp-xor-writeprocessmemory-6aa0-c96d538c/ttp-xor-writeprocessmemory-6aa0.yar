rule TTP_XOR_WriteProcessMemory_6aa0 {
  strings:
    $key_6aa0 = { 3d d2 [2] 0f f0 [2] 09 c5 [2] 27 c5 [2] 18 d9 }

  condition:
    any of them
}