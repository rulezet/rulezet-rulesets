rule TTP_XOR_WriteProcessMemory_17ea {
  strings:
    $key_17ea = { 40 98 [2] 72 ba [2] 74 8f [2] 5a 8f [2] 65 93 }

  condition:
    any of them
}