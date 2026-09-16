rule TTP_XOR_WriteProcessMemory_e923 {
  strings:
    $key_e923 = { be 51 [2] 8c 73 [2] 8a 46 [2] a4 46 [2] 9b 5a }

  condition:
    any of them
}