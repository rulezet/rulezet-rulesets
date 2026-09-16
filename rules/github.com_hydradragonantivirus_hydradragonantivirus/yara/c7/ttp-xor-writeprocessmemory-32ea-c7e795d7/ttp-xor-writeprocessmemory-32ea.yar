rule TTP_XOR_WriteProcessMemory_32ea {
  strings:
    $key_32ea = { 65 98 [2] 57 ba [2] 51 8f [2] 7f 8f [2] 40 93 }

  condition:
    any of them
}