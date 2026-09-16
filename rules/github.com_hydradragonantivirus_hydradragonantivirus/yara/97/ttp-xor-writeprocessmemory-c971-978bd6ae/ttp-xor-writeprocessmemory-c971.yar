rule TTP_XOR_WriteProcessMemory_c971 {
  strings:
    $key_c971 = { 9e 03 [2] ac 21 [2] aa 14 [2] 84 14 [2] bb 08 }

  condition:
    any of them
}