rule TTP_XOR_WriteProcessMemory_c9c5 {
  strings:
    $key_c9c5 = { 9e b7 [2] ac 95 [2] aa a0 [2] 84 a0 [2] bb bc }

  condition:
    any of them
}