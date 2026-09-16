rule TTP_XOR_WriteProcessMemory_60b3 {
  strings:
    $key_60b3 = { 37 c1 [2] 05 e3 [2] 03 d6 [2] 2d d6 [2] 12 ca }

  condition:
    any of them
}