rule TTP_XOR_WriteProcessMemory_8efc {
  strings:
    $key_8efc = { d9 8e [2] eb ac [2] ed 99 [2] c3 99 [2] fc 85 }

  condition:
    any of them
}