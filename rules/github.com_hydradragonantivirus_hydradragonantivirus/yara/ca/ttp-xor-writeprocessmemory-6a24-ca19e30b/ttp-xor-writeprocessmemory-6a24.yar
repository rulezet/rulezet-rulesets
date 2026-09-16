rule TTP_XOR_WriteProcessMemory_6a24 {
  strings:
    $key_6a24 = { 3d 56 [2] 0f 74 [2] 09 41 [2] 27 41 [2] 18 5d }

  condition:
    any of them
}