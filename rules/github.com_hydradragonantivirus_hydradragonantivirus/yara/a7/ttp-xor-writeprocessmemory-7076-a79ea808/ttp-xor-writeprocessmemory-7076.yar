rule TTP_XOR_WriteProcessMemory_7076 {
  strings:
    $key_7076 = { 27 04 [2] 15 26 [2] 13 13 [2] 3d 13 [2] 02 0f }

  condition:
    any of them
}