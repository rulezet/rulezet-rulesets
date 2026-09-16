rule TTP_XOR_WriteProcessMemory_6444 {
  strings:
    $key_6444 = { 33 36 [2] 01 14 [2] 07 21 [2] 29 21 [2] 16 3d }

  condition:
    any of them
}