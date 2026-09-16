rule TTP_XOR_WriteProcessMemory_47ea {
  strings:
    $key_47ea = { 10 98 [2] 22 ba [2] 24 8f [2] 0a 8f [2] 35 93 }

  condition:
    any of them
}