rule TTP_XOR_WriteProcessMemory_48a4 {
  strings:
    $key_48a4 = { 1f d6 [2] 2d f4 [2] 2b c1 [2] 05 c1 [2] 3a dd }

  condition:
    any of them
}