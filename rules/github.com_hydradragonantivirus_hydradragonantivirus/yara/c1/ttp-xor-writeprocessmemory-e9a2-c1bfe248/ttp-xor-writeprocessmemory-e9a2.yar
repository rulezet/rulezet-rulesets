rule TTP_XOR_WriteProcessMemory_e9a2 {
  strings:
    $key_e9a2 = { be d0 [2] 8c f2 [2] 8a c7 [2] a4 c7 [2] 9b db }

  condition:
    any of them
}