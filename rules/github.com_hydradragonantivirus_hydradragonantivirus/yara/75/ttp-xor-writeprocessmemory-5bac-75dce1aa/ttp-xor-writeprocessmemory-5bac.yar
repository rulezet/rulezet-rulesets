rule TTP_XOR_WriteProcessMemory_5bac {
  strings:
    $key_5bac = { 0c de [2] 3e fc [2] 38 c9 [2] 16 c9 [2] 29 d5 }

  condition:
    any of them
}