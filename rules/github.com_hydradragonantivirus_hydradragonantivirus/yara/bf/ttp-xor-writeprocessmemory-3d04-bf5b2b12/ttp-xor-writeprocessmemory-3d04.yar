rule TTP_XOR_WriteProcessMemory_3d04 {
  strings:
    $key_3d04 = { 6a 76 [2] 58 54 [2] 5e 61 [2] 70 61 [2] 4f 7d }

  condition:
    any of them
}