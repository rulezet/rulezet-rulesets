rule TTP_XOR_WriteProcessMemory_70c9 {
  strings:
    $key_70c9 = { 27 bb [2] 15 99 [2] 13 ac [2] 3d ac [2] 02 b0 }

  condition:
    any of them
}