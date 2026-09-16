rule TTP_XOR_WriteProcessMemory_6ae4 {
  strings:
    $key_6ae4 = { 3d 96 [2] 0f b4 [2] 09 81 [2] 27 81 [2] 18 9d }

  condition:
    any of them
}