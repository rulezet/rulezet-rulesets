rule TTP_XOR_WriteProcessMemory_7007 {
  strings:
    $key_7007 = { 27 75 [2] 15 57 [2] 13 62 [2] 3d 62 [2] 02 7e }

  condition:
    any of them
}