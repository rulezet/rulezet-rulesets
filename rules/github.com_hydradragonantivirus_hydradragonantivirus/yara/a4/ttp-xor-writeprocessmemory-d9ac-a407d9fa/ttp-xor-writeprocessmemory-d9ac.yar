rule TTP_XOR_WriteProcessMemory_d9ac {
  strings:
    $key_d9ac = { 8e de [2] bc fc [2] ba c9 [2] 94 c9 [2] ab d5 }

  condition:
    any of them
}