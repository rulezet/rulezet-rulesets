rule TTP_XOR_WriteProcessMemory_03e1 {
  strings:
    $key_03e1 = { 54 93 [2] 66 b1 [2] 60 84 [2] 4e 84 [2] 71 98 }

  condition:
    any of them
}