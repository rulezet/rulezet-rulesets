rule TTP_XOR_WriteProcessMemory_70d5 {
  strings:
    $key_70d5 = { 27 a7 [2] 15 85 [2] 13 b0 [2] 3d b0 [2] 02 ac }

  condition:
    any of them
}