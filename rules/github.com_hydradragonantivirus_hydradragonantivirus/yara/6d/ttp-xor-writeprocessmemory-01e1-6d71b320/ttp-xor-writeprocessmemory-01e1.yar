rule TTP_XOR_WriteProcessMemory_01e1 {
  strings:
    $key_01e1 = { 56 93 [2] 64 b1 [2] 62 84 [2] 4c 84 [2] 73 98 }

  condition:
    any of them
}