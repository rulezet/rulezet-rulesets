rule TTP_XOR_WriteProcessMemory_6af2 {
  strings:
    $key_6af2 = { 3d 80 [2] 0f a2 [2] 09 97 [2] 27 97 [2] 18 8b }

  condition:
    any of them
}