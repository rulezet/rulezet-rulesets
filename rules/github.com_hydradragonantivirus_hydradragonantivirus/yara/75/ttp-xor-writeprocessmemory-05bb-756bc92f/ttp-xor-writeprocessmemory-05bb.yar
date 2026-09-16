rule TTP_XOR_WriteProcessMemory_05bb {
  strings:
    $key_05bb = { 52 c9 [2] 60 eb [2] 66 de [2] 48 de [2] 77 c2 }

  condition:
    any of them
}