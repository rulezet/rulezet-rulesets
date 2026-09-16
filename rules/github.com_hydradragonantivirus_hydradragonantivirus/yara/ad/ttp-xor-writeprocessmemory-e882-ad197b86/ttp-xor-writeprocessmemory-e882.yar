rule TTP_XOR_WriteProcessMemory_e882 {
  strings:
    $key_e882 = { bf f0 [2] 8d d2 [2] 8b e7 [2] a5 e7 [2] 9a fb }

  condition:
    any of them
}