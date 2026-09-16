rule TTP_XOR_WriteProcessMemory_c98b {
  strings:
    $key_c98b = { 9e f9 [2] ac db [2] aa ee [2] 84 ee [2] bb f2 }

  condition:
    any of them
}