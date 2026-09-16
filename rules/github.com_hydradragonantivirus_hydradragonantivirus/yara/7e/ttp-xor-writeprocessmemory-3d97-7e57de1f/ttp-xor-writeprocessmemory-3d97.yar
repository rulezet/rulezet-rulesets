rule TTP_XOR_WriteProcessMemory_3d97 {
  strings:
    $key_3d97 = { 6a e5 [2] 58 c7 [2] 5e f2 [2] 70 f2 [2] 4f ee }

  condition:
    any of them
}