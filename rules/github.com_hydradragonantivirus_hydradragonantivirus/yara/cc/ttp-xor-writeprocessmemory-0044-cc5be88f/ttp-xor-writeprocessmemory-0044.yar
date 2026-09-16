rule TTP_XOR_WriteProcessMemory_0044 {
  strings:
    $key_0044 = { 57 36 [2] 65 14 [2] 63 21 [2] 4d 21 [2] 72 3d }

  condition:
    any of them
}