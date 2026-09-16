rule TTP_XOR_WriteProcessMemory_be91 {
  strings:
    $key_be91 = { e9 e3 [2] db c1 [2] dd f4 [2] f3 f4 [2] cc e8 }

  condition:
    any of them
}