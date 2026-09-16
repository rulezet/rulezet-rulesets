rule TTP_XOR_WriteProcessMemory_a2ea {
  strings:
    $key_a2ea = { f5 98 [2] c7 ba [2] c1 8f [2] ef 8f [2] d0 93 }

  condition:
    any of them
}