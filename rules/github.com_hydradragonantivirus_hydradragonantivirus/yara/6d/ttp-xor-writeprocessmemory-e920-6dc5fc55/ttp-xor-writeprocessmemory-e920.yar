rule TTP_XOR_WriteProcessMemory_e920 {
  strings:
    $key_e920 = { be 52 [2] 8c 70 [2] 8a 45 [2] a4 45 [2] 9b 59 }

  condition:
    any of them
}