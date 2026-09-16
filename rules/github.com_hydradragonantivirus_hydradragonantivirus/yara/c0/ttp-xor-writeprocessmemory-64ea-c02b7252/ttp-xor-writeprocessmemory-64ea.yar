rule TTP_XOR_WriteProcessMemory_64ea {
  strings:
    $key_64ea = { 33 98 [2] 01 ba [2] 07 8f [2] 29 8f [2] 16 93 }

  condition:
    any of them
}