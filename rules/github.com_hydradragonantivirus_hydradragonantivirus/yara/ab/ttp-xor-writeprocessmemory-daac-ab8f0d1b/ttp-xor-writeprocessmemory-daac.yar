rule TTP_XOR_WriteProcessMemory_daac {
  strings:
    $key_daac = { 8d de [2] bf fc [2] b9 c9 [2] 97 c9 [2] a8 d5 }

  condition:
    any of them
}