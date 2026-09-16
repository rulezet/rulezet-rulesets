rule TTP_XOR_WriteProcessMemory_ded7 {
  strings:
    $key_ded7 = { 89 a5 [2] bb 87 [2] bd b2 [2] 93 b2 [2] ac ae }

  condition:
    any of them
}