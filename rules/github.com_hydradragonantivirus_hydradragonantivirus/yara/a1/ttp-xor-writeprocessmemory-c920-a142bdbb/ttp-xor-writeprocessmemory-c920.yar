rule TTP_XOR_WriteProcessMemory_c920 {
  strings:
    $key_c920 = { 9e 52 [2] ac 70 [2] aa 45 [2] 84 45 [2] bb 59 }

  condition:
    any of them
}