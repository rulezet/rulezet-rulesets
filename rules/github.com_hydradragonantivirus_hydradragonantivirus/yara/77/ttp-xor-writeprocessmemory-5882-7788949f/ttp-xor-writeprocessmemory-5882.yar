rule TTP_XOR_WriteProcessMemory_5882 {
  strings:
    $key_5882 = { 0f f0 [2] 3d d2 [2] 3b e7 [2] 15 e7 [2] 2a fb }

  condition:
    any of them
}