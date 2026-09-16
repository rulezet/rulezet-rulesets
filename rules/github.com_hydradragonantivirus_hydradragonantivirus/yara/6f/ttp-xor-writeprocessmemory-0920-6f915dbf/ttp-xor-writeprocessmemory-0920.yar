rule TTP_XOR_WriteProcessMemory_0920 {
  strings:
    $key_0920 = { 5e 52 [2] 6c 70 [2] 6a 45 [2] 44 45 [2] 7b 59 }

  condition:
    any of them
}