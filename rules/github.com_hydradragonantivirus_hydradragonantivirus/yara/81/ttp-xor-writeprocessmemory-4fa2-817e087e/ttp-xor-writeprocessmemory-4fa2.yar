rule TTP_XOR_WriteProcessMemory_4fa2 {
  strings:
    $key_4fa2 = { 18 d0 [2] 2a f2 [2] 2c c7 [2] 02 c7 [2] 3d db }

  condition:
    any of them
}