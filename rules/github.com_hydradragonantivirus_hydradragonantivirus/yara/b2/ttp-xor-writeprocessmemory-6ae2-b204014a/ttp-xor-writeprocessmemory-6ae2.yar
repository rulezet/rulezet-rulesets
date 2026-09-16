rule TTP_XOR_WriteProcessMemory_6ae2 {
  strings:
    $key_6ae2 = { 3d 90 [2] 0f b2 [2] 09 87 [2] 27 87 [2] 18 9b }

  condition:
    any of them
}