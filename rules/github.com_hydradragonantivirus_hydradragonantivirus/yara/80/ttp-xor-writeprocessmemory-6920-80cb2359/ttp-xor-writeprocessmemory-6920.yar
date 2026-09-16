rule TTP_XOR_WriteProcessMemory_6920 {
  strings:
    $key_6920 = { 3e 52 [2] 0c 70 [2] 0a 45 [2] 24 45 [2] 1b 59 }

  condition:
    any of them
}