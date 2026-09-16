rule TTP_XOR_WriteProcessMemory_a0ea {
  strings:
    $key_a0ea = { f7 98 [2] c5 ba [2] c3 8f [2] ed 8f [2] d2 93 }

  condition:
    any of them
}