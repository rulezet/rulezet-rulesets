rule TTP_XOR_WriteProcessMemory_6092 {
  strings:
    $key_6092 = { 37 e0 [2] 05 c2 [2] 03 f7 [2] 2d f7 [2] 12 eb }

  condition:
    any of them
}