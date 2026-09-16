rule TTP_XOR_WriteProcessMemory_c950 {
  strings:
    $key_c950 = { 9e 22 [2] ac 00 [2] aa 35 [2] 84 35 [2] bb 29 }

  condition:
    any of them
}