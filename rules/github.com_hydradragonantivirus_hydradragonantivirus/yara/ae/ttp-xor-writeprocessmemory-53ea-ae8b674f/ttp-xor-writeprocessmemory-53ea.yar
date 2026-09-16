rule TTP_XOR_WriteProcessMemory_53ea {
  strings:
    $key_53ea = { 04 98 [2] 36 ba [2] 30 8f [2] 1e 8f [2] 21 93 }

  condition:
    any of them
}