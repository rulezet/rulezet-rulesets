rule TTP_XOR_WriteProcessMemory_7051 {
  strings:
    $key_7051 = { 27 23 [2] 15 01 [2] 13 34 [2] 3d 34 [2] 02 28 }

  condition:
    any of them
}