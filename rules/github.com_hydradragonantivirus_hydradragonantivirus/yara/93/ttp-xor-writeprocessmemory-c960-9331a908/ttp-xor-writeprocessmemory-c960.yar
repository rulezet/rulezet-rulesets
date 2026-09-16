rule TTP_XOR_WriteProcessMemory_c960 {
  strings:
    $key_c960 = { 9e 12 [2] ac 30 [2] aa 05 [2] 84 05 [2] bb 19 }

  condition:
    any of them
}