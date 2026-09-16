rule TTP_XOR_WriteProcessMemory_44ea {
  strings:
    $key_44ea = { 13 98 [2] 21 ba [2] 27 8f [2] 09 8f [2] 36 93 }

  condition:
    any of them
}