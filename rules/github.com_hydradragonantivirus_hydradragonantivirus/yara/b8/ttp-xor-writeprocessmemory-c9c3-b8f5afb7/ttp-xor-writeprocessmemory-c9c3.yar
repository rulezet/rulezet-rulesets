rule TTP_XOR_WriteProcessMemory_c9c3 {
  strings:
    $key_c9c3 = { 9e b1 [2] ac 93 [2] aa a6 [2] 84 a6 [2] bb ba }

  condition:
    any of them
}