rule TTP_XOR_WriteProcessMemory_11ea {
  strings:
    $key_11ea = { 46 98 [2] 74 ba [2] 72 8f [2] 5c 8f [2] 63 93 }

  condition:
    any of them
}