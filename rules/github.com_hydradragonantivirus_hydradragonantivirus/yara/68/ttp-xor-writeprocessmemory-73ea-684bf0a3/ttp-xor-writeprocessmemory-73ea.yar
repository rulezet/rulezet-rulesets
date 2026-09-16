rule TTP_XOR_WriteProcessMemory_73ea {
  strings:
    $key_73ea = { 24 98 [2] 16 ba [2] 10 8f [2] 3e 8f [2] 01 93 }

  condition:
    any of them
}