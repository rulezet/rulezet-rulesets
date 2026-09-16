rule TTP_XOR_WriteProcessMemory_0544 {
  strings:
    $key_0544 = { 52 36 [2] 60 14 [2] 66 21 [2] 48 21 [2] 77 3d }

  condition:
    any of them
}