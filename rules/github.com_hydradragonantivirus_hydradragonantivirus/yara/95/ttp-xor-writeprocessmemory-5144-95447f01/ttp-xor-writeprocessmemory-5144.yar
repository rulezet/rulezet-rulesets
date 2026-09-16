rule TTP_XOR_WriteProcessMemory_5144 {
  strings:
    $key_5144 = { 06 36 [2] 34 14 [2] 32 21 [2] 1c 21 [2] 23 3d }

  condition:
    any of them
}