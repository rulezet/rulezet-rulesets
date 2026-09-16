rule TTP_XOR_WriteProcessMemory_7544 {
  strings:
    $key_7544 = { 22 36 [2] 10 14 [2] 16 21 [2] 38 21 [2] 07 3d }

  condition:
    any of them
}