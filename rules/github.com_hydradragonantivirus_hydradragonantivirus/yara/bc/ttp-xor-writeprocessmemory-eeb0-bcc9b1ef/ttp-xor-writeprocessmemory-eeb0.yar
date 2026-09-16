rule TTP_XOR_WriteProcessMemory_eeb0 {
  strings:
    $key_eeb0 = { b9 c2 [2] 8b e0 [2] 8d d5 [2] a3 d5 [2] 9c c9 }

  condition:
    any of them
}