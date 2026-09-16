rule TTP_XOR_WriteProcessMemory_3d74 {
  strings:
    $key_3d74 = { 6a 06 [2] 58 24 [2] 5e 11 [2] 70 11 [2] 4f 0d }

  condition:
    any of them
}