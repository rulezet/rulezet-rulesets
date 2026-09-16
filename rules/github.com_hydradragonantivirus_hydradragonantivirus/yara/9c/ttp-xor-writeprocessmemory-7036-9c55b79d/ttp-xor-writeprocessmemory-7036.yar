rule TTP_XOR_WriteProcessMemory_7036 {
  strings:
    $key_7036 = { 27 44 [2] 15 66 [2] 13 53 [2] 3d 53 [2] 02 4f }

  condition:
    any of them
}