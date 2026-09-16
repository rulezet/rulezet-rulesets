rule TTP_XOR_WriteProcessMemory_6ac2 {
  strings:
    $key_6ac2 = { 3d b0 [2] 0f 92 [2] 09 a7 [2] 27 a7 [2] 18 bb }

  condition:
    any of them
}