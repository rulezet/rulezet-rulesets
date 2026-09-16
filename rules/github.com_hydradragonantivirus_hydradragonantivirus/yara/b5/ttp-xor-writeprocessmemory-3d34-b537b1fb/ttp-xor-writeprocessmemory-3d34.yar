rule TTP_XOR_WriteProcessMemory_3d34 {
  strings:
    $key_3d34 = { 6a 46 [2] 58 64 [2] 5e 51 [2] 70 51 [2] 4f 4d }

  condition:
    any of them
}