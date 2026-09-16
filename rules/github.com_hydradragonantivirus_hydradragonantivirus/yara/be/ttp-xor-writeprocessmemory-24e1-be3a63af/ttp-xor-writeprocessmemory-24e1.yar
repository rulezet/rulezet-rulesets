rule TTP_XOR_WriteProcessMemory_24e1 {
  strings:
    $key_24e1 = { 73 93 [2] 41 b1 [2] 47 84 [2] 69 84 [2] 56 98 }

  condition:
    any of them
}