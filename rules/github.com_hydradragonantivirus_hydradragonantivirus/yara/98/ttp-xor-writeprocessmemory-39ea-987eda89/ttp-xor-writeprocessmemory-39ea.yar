rule TTP_XOR_WriteProcessMemory_39ea {
  strings:
    $key_39ea = { 6e 98 [2] 5c ba [2] 5a 8f [2] 74 8f [2] 4b 93 }

  condition:
    any of them
}