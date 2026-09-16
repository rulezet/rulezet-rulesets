rule TTP_XOR_WriteProcessMemory_6a54 {
  strings:
    $key_6a54 = { 3d 26 [2] 0f 04 [2] 09 31 [2] 27 31 [2] 18 2d }

  condition:
    any of them
}