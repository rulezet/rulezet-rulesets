rule TTP_XOR_WriteProcessMemory_6a36 {
  strings:
    $key_6a36 = { 3d 44 [2] 0f 66 [2] 09 53 [2] 27 53 [2] 18 4f }

  condition:
    any of them
}