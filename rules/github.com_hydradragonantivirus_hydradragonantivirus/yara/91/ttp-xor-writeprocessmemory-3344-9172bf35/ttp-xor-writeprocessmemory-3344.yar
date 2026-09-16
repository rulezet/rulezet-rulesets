rule TTP_XOR_WriteProcessMemory_3344 {
  strings:
    $key_3344 = { 64 36 [2] 56 14 [2] 50 21 [2] 7e 21 [2] 41 3d }

  condition:
    any of them
}