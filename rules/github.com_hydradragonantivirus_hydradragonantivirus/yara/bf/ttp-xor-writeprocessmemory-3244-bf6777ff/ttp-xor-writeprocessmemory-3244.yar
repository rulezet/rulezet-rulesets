rule TTP_XOR_WriteProcessMemory_3244 {
  strings:
    $key_3244 = { 65 36 [2] 57 14 [2] 51 21 [2] 7f 21 [2] 40 3d }

  condition:
    any of them
}