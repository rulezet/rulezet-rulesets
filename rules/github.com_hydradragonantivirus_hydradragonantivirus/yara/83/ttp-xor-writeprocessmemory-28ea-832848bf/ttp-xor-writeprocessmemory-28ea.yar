rule TTP_XOR_WriteProcessMemory_28ea {
  strings:
    $key_28ea = { 7f 98 [2] 4d ba [2] 4b 8f [2] 65 8f [2] 5a 93 }

  condition:
    any of them
}