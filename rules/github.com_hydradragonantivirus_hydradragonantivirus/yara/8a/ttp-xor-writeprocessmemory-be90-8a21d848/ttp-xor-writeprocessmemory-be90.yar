rule TTP_XOR_WriteProcessMemory_be90 {
  strings:
    $key_be90 = { e9 e2 [2] db c0 [2] dd f5 [2] f3 f5 [2] cc e9 }

  condition:
    any of them
}