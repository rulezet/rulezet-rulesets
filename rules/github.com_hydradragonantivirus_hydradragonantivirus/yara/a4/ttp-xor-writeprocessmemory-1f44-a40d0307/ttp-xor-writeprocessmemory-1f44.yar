rule TTP_XOR_WriteProcessMemory_1f44 {
  strings:
    $key_1f44 = { 48 36 [2] 7a 14 [2] 7c 21 [2] 52 21 [2] 6d 3d }

  condition:
    any of them
}