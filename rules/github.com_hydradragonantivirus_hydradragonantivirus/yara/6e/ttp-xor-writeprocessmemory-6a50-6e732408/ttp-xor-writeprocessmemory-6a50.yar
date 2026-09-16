rule TTP_XOR_WriteProcessMemory_6a50 {
  strings:
    $key_6a50 = { 3d 22 [2] 0f 00 [2] 09 35 [2] 27 35 [2] 18 29 }

  condition:
    any of them
}