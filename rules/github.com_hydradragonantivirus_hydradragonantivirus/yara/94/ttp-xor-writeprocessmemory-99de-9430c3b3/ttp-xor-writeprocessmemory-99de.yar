rule TTP_XOR_WriteProcessMemory_99de {
  strings:
    $key_99de = { ce ac [2] fc 8e [2] fa bb [2] d4 bb [2] eb a7 }

  condition:
    any of them
}