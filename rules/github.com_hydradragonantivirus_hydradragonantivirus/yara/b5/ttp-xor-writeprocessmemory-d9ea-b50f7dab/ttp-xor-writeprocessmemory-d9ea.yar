rule TTP_XOR_WriteProcessMemory_d9ea {
  strings:
    $key_d9ea = { 8e 98 [2] bc ba [2] ba 8f [2] 94 8f [2] ab 93 }

  condition:
    any of them
}