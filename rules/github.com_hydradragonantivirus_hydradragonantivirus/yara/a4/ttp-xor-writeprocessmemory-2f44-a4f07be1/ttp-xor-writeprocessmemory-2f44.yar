rule TTP_XOR_WriteProcessMemory_2f44 {
  strings:
    $key_2f44 = { 78 36 [2] 4a 14 [2] 4c 21 [2] 62 21 [2] 5d 3d }

  condition:
    any of them
}