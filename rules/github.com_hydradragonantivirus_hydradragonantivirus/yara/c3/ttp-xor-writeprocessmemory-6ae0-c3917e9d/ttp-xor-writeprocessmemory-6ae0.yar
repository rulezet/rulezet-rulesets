rule TTP_XOR_WriteProcessMemory_6ae0 {
  strings:
    $key_6ae0 = { 3d 92 [2] 0f b0 [2] 09 85 [2] 27 85 [2] 18 99 }

  condition:
    any of them
}