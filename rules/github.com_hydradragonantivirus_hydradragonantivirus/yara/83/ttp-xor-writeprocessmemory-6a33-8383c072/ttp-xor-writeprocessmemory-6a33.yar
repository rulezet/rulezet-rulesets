rule TTP_XOR_WriteProcessMemory_6a33 {
  strings:
    $key_6a33 = { 3d 41 [2] 0f 63 [2] 09 56 [2] 27 56 [2] 18 4a }

  condition:
    any of them
}