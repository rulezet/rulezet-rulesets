rule TTP_XOR_WriteProcessMemory_c932 {
  strings:
    $key_c932 = { 9e 40 [2] ac 62 [2] aa 57 [2] 84 57 [2] bb 4b }

  condition:
    any of them
}