rule TTP_XOR_WriteProcessMemory_e913 {
  strings:
    $key_e913 = { be 61 [2] 8c 43 [2] 8a 76 [2] a4 76 [2] 9b 6a }

  condition:
    any of them
}