rule TTP_XOR_WriteProcessMemory_d8ac {
  strings:
    $key_d8ac = { 8f de [2] bd fc [2] bb c9 [2] 95 c9 [2] aa d5 }

  condition:
    any of them
}