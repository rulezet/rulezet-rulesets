rule TTP_XOR_WriteProcessMemory_e973 {
  strings:
    $key_e973 = { be 01 [2] 8c 23 [2] 8a 16 [2] a4 16 [2] 9b 0a }

  condition:
    any of them
}