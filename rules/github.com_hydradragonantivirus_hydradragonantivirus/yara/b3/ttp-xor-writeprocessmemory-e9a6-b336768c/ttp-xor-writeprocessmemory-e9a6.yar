rule TTP_XOR_WriteProcessMemory_e9a6 {
  strings:
    $key_e9a6 = { be d4 [2] 8c f6 [2] 8a c3 [2] a4 c3 [2] 9b df }

  condition:
    any of them
}