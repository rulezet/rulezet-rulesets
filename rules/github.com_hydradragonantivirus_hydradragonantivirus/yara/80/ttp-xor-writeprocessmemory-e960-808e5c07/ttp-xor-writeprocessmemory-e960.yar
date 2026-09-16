rule TTP_XOR_WriteProcessMemory_e960 {
  strings:
    $key_e960 = { be 12 [2] 8c 30 [2] 8a 05 [2] a4 05 [2] 9b 19 }

  condition:
    any of them
}