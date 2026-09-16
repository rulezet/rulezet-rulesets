rule TTP_XOR_WriteProcessMemory_e4ea {
  strings:
    $key_e4ea = { b3 98 [2] 81 ba [2] 87 8f [2] a9 8f [2] 96 93 }

  condition:
    any of them
}