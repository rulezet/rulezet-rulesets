rule TTP_XOR_WriteProcessMemory_6a52 {
  strings:
    $key_6a52 = { 3d 20 [2] 0f 02 [2] 09 37 [2] 27 37 [2] 18 2b }

  condition:
    any of them
}