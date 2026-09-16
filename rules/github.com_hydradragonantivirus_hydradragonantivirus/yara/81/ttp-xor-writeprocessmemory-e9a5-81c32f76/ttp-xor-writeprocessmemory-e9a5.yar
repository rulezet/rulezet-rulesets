rule TTP_XOR_WriteProcessMemory_e9a5 {
  strings:
    $key_e9a5 = { be d7 [2] 8c f5 [2] 8a c0 [2] a4 c0 [2] 9b dc }

  condition:
    any of them
}