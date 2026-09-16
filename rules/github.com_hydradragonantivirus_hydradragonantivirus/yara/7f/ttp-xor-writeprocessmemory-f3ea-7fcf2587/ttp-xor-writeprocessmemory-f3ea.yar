rule TTP_XOR_WriteProcessMemory_f3ea {
  strings:
    $key_f3ea = { a4 98 [2] 96 ba [2] 90 8f [2] be 8f [2] 81 93 }

  condition:
    any of them
}