rule TTP_XOR_WriteProcessMemory_6a62 {
  strings:
    $key_6a62 = { 3d 10 [2] 0f 32 [2] 09 07 [2] 27 07 [2] 18 1b }

  condition:
    any of them
}