rule TTP_XOR_WriteProcessMemory_e9a7 {
  strings:
    $key_e9a7 = { be d5 [2] 8c f7 [2] 8a c2 [2] a4 c2 [2] 9b de }

  condition:
    any of them
}