rule TTP_XOR_WriteProcessMemory_48a2 {
  strings:
    $key_48a2 = { 1f d0 [2] 2d f2 [2] 2b c7 [2] 05 c7 [2] 3a db }

  condition:
    any of them
}