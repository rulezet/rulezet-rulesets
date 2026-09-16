rule TTP_XOR_WriteProcessMemory_31e1 {
  strings:
    $key_31e1 = { 66 93 [2] 54 b1 [2] 52 84 [2] 7c 84 [2] 43 98 }

  condition:
    any of them
}