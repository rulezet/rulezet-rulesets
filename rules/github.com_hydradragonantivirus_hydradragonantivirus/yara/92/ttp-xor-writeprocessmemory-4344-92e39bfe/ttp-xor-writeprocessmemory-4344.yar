rule TTP_XOR_WriteProcessMemory_4344 {
  strings:
    $key_4344 = { 14 36 [2] 26 14 [2] 20 21 [2] 0e 21 [2] 31 3d }

  condition:
    any of them
}