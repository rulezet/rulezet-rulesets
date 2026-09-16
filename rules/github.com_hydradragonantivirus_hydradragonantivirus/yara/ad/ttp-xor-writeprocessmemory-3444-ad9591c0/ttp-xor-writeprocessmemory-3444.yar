rule TTP_XOR_WriteProcessMemory_3444 {
  strings:
    $key_3444 = { 63 36 [2] 51 14 [2] 57 21 [2] 79 21 [2] 46 3d }

  condition:
    any of them
}