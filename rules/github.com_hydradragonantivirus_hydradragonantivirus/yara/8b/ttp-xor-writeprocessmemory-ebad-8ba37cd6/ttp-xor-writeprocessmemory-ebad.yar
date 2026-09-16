rule TTP_XOR_WriteProcessMemory_ebad {
  strings:
    $key_ebad = { bc df [2] 8e fd [2] 88 c8 [2] a6 c8 [2] 99 d4 }

  condition:
    any of them
}