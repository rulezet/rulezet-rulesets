rule TTP_XOR_WriteProcessMemory_31ea {
  strings:
    $key_31ea = { 66 98 [2] 54 ba [2] 52 8f [2] 7c 8f [2] 43 93 }

  condition:
    any of them
}