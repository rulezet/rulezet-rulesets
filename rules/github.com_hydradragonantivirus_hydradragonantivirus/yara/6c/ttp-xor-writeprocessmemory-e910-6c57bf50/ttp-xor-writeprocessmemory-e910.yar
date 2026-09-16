rule TTP_XOR_WriteProcessMemory_e910 {
  strings:
    $key_e910 = { be 62 [2] 8c 40 [2] 8a 75 [2] a4 75 [2] 9b 69 }

  condition:
    any of them
}