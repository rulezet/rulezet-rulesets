rule TTP_XOR_WriteProcessMemory_3d76 {
  strings:
    $key_3d76 = { 6a 04 [2] 58 26 [2] 5e 13 [2] 70 13 [2] 4f 0f }

  condition:
    any of them
}