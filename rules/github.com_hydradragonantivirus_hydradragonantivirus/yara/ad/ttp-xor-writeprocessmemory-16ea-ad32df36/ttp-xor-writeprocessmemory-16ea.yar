rule TTP_XOR_WriteProcessMemory_16ea {
  strings:
    $key_16ea = { 41 98 [2] 73 ba [2] 75 8f [2] 5b 8f [2] 64 93 }

  condition:
    any of them
}