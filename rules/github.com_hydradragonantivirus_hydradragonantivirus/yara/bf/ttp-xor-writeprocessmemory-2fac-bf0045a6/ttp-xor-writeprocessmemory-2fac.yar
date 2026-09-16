rule TTP_XOR_WriteProcessMemory_2fac {
  strings:
    $key_2fac = { 78 de [2] 4a fc [2] 4c c9 [2] 62 c9 [2] 5d d5 }

  condition:
    any of them
}