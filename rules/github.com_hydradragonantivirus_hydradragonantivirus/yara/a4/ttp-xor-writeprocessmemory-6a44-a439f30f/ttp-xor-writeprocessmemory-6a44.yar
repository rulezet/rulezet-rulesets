rule TTP_XOR_WriteProcessMemory_6a44 {
  strings:
    $key_6a44 = { 3d 36 [2] 0f 14 [2] 09 21 [2] 27 21 [2] 18 3d }

  condition:
    any of them
}