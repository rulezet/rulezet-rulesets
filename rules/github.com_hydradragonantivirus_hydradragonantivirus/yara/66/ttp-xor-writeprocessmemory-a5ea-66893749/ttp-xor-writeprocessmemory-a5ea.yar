rule TTP_XOR_WriteProcessMemory_a5ea {
  strings:
    $key_a5ea = { f2 98 [2] c0 ba [2] c6 8f [2] e8 8f [2] d7 93 }

  condition:
    any of them
}