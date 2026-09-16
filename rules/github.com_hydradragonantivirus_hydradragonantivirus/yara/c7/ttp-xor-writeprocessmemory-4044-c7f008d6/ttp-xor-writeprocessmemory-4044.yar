rule TTP_XOR_WriteProcessMemory_4044 {
  strings:
    $key_4044 = { 17 36 [2] 25 14 [2] 23 21 [2] 0d 21 [2] 32 3d }

  condition:
    any of them
}