rule TTP_XOR_WriteProcessMemory_be98 {
  strings:
    $key_be98 = { e9 ea [2] db c8 [2] dd fd [2] f3 fd [2] cc e1 }

  condition:
    any of them
}