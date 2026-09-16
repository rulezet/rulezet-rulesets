rule TTP_XOR_WriteProcessMemory_c900 {
  strings:
    $key_c900 = { 9e 72 [2] ac 50 [2] aa 65 [2] 84 65 [2] bb 79 }

  condition:
    any of them
}