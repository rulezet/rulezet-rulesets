rule TTP_XOR_WriteProcessMemory_cbac {
  strings:
    $key_cbac = { 9c de [2] ae fc [2] a8 c9 [2] 86 c9 [2] b9 d5 }

  condition:
    any of them
}