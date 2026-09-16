rule TTP_XOR_WriteProcessMemory_b2ea {
  strings:
    $key_b2ea = { e5 98 [2] d7 ba [2] d1 8f [2] ff 8f [2] c0 93 }

  condition:
    any of them
}