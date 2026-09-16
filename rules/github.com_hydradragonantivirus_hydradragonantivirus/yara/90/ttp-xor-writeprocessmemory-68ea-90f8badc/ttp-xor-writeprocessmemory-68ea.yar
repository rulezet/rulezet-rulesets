rule TTP_XOR_WriteProcessMemory_68ea {
  strings:
    $key_68ea = { 3f 98 [2] 0d ba [2] 0b 8f [2] 25 8f [2] 1a 93 }

  condition:
    any of them
}