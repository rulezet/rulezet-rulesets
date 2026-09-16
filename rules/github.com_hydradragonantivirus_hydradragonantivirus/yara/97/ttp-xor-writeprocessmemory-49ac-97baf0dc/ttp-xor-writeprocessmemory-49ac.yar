rule TTP_XOR_WriteProcessMemory_49ac {
  strings:
    $key_49ac = { 1e de [2] 2c fc [2] 2a c9 [2] 04 c9 [2] 3b d5 }

  condition:
    any of them
}