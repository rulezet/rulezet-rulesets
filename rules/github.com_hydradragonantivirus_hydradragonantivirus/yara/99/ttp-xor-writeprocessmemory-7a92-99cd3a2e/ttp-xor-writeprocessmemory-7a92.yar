rule TTP_XOR_WriteProcessMemory_7a92 {
  strings:
    $key_7a92 = { 2d e0 [2] 1f c2 [2] 19 f7 [2] 37 f7 [2] 08 eb }

  condition:
    any of them
}