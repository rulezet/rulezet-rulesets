rule TTP_XOR_WriteProcessMemory_e444 {
  strings:
    $key_e444 = { b3 36 [2] 81 14 [2] 87 21 [2] a9 21 [2] 96 3d }

  condition:
    any of them
}