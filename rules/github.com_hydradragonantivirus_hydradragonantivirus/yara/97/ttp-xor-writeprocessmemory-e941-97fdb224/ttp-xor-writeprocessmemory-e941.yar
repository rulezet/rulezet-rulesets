rule TTP_XOR_WriteProcessMemory_e941 {
  strings:
    $key_e941 = { be 33 [2] 8c 11 [2] 8a 24 [2] a4 24 [2] 9b 38 }

  condition:
    any of them
}