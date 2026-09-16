rule TTP_XOR_WriteProcessMemory_4bac {
  strings:
    $key_4bac = { 1c de [2] 2e fc [2] 28 c9 [2] 06 c9 [2] 39 d5 }

  condition:
    any of them
}