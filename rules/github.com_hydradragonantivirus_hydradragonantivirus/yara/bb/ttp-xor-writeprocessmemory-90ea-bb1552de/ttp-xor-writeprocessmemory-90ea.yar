rule TTP_XOR_WriteProcessMemory_90ea {
  strings:
    $key_90ea = { c7 98 [2] f5 ba [2] f3 8f [2] dd 8f [2] e2 93 }

  condition:
    any of them
}