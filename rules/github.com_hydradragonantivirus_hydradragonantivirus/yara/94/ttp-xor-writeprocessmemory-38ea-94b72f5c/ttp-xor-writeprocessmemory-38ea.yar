rule TTP_XOR_WriteProcessMemory_38ea {
  strings:
    $key_38ea = { 6f 98 [2] 5d ba [2] 5b 8f [2] 75 8f [2] 4a 93 }

  condition:
    any of them
}