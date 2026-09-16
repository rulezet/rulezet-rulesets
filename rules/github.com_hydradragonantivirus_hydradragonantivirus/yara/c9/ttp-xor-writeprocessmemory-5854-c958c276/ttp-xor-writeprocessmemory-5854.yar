rule TTP_XOR_WriteProcessMemory_5854 {
  strings:
    $key_5854 = { 0f 26 [2] 3d 04 [2] 3b 31 [2] 15 31 [2] 2a 2d }

  condition:
    any of them
}