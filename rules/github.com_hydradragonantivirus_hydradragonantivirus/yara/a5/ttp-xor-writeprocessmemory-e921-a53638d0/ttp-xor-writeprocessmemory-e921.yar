rule TTP_XOR_WriteProcessMemory_e921 {
  strings:
    $key_e921 = { be 53 [2] 8c 71 [2] 8a 44 [2] a4 44 [2] 9b 58 }

  condition:
    any of them
}