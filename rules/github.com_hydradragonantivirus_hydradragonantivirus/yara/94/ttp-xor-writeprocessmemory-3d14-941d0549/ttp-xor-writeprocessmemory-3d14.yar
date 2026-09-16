rule TTP_XOR_WriteProcessMemory_3d14 {
  strings:
    $key_3d14 = { 6a 66 [2] 58 44 [2] 5e 71 [2] 70 71 [2] 4f 6d }

  condition:
    any of them
}