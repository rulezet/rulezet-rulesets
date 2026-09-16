rule TTP_XOR_WriteProcessMemory_6a92 {
  strings:
    $key_6a92 = { 3d e0 [2] 0f c2 [2] 09 f7 [2] 27 f7 [2] 18 eb }

  condition:
    any of them
}