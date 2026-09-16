rule TTP_XOR_WriteProcessMemory_c9d1 {
  strings:
    $key_c9d1 = { 9e a3 [2] ac 81 [2] aa b4 [2] 84 b4 [2] bb a8 }

  condition:
    any of them
}