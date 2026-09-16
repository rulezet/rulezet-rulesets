rule TTP_XOR_WriteProcessMemory_79ac {
  strings:
    $key_79ac = { 2e de [2] 1c fc [2] 1a c9 [2] 34 c9 [2] 0b d5 }

  condition:
    any of them
}