rule TTP_XOR_WriteProcessMemory_be9b {
  strings:
    $key_be9b = { e9 e9 [2] db cb [2] dd fe [2] f3 fe [2] cc e2 }

  condition:
    any of them
}