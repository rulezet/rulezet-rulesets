rule TTP_XOR_WriteProcessMemory_52e1 {
  strings:
    $key_52e1 = { 05 93 [2] 37 b1 [2] 31 84 [2] 1f 84 [2] 20 98 }

  condition:
    any of them
}