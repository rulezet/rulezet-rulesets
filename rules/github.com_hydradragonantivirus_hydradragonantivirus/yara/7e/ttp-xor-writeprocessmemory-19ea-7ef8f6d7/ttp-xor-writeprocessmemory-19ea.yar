rule TTP_XOR_WriteProcessMemory_19ea {
  strings:
    $key_19ea = { 4e 98 [2] 7c ba [2] 7a 8f [2] 54 8f [2] 6b 93 }

  condition:
    any of them
}