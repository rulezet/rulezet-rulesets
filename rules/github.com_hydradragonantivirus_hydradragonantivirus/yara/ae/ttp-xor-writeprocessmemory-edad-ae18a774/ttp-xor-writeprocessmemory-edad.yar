rule TTP_XOR_WriteProcessMemory_edad {
  strings:
    $key_edad = { ba df [2] 88 fd [2] 8e c8 [2] a0 c8 [2] 9f d4 }

  condition:
    any of them
}