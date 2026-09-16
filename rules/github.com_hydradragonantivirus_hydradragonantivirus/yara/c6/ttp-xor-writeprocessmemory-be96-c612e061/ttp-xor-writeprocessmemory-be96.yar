rule TTP_XOR_WriteProcessMemory_be96 {
  strings:
    $key_be96 = { e9 e4 [2] db c6 [2] dd f3 [2] f3 f3 [2] cc ef }

  condition:
    any of them
}