rule TTP_XOR_WriteProcessMemory_6bac {
  strings:
    $key_6bac = { 3c de [2] 0e fc [2] 08 c9 [2] 26 c9 [2] 19 d5 }

  condition:
    any of them
}