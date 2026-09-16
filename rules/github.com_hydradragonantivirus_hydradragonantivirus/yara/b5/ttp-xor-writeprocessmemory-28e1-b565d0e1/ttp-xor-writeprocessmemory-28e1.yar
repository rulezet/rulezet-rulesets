rule TTP_XOR_WriteProcessMemory_28e1 {
  strings:
    $key_28e1 = { 7f 93 [2] 4d b1 [2] 4b 84 [2] 65 84 [2] 5a 98 }

  condition:
    any of them
}