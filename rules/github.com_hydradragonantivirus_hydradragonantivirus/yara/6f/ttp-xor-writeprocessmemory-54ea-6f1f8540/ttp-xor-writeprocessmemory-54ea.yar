rule TTP_XOR_WriteProcessMemory_54ea {
  strings:
    $key_54ea = { 03 98 [2] 31 ba [2] 37 8f [2] 19 8f [2] 26 93 }

  condition:
    any of them
}