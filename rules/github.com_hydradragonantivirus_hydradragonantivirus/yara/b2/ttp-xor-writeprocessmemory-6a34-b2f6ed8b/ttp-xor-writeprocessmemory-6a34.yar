rule TTP_XOR_WriteProcessMemory_6a34 {
  strings:
    $key_6a34 = { 3d 46 [2] 0f 64 [2] 09 51 [2] 27 51 [2] 18 4d }

  condition:
    any of them
}