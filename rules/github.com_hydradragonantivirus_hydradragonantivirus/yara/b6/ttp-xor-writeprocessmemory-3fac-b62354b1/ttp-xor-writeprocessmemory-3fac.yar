rule TTP_XOR_WriteProcessMemory_3fac {
  strings:
    $key_3fac = { 68 de [2] 5a fc [2] 5c c9 [2] 72 c9 [2] 4d d5 }

  condition:
    any of them
}