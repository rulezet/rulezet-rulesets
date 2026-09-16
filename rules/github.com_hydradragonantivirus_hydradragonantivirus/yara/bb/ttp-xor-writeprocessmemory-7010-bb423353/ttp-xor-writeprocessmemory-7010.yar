rule TTP_XOR_WriteProcessMemory_7010 {
  strings:
    $key_7010 = { 27 62 [2] 15 40 [2] 13 75 [2] 3d 75 [2] 02 69 }

  condition:
    any of them
}