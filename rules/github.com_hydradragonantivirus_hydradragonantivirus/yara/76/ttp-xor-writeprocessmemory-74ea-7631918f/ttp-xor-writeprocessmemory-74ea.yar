rule TTP_XOR_WriteProcessMemory_74ea {
  strings:
    $key_74ea = { 23 98 [2] 11 ba [2] 17 8f [2] 39 8f [2] 06 93 }

  condition:
    any of them
}