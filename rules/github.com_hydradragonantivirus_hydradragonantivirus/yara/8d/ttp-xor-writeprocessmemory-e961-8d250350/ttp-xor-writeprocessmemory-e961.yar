rule TTP_XOR_WriteProcessMemory_e961 {
  strings:
    $key_e961 = { be 13 [2] 8c 31 [2] 8a 04 [2] a4 04 [2] 9b 18 }

  condition:
    any of them
}