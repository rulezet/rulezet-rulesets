rule TTP_XOR_WriteProcessMemory_40ea {
  strings:
    $key_40ea = { 17 98 [2] 25 ba [2] 23 8f [2] 0d 8f [2] 32 93 }

  condition:
    any of them
}