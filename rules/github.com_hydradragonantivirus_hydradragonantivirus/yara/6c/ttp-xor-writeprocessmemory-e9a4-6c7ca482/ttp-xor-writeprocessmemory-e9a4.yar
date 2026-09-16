rule TTP_XOR_WriteProcessMemory_e9a4 {
  strings:
    $key_e9a4 = { be d6 [2] 8c f4 [2] 8a c1 [2] a4 c1 [2] 9b dd }

  condition:
    any of them
}