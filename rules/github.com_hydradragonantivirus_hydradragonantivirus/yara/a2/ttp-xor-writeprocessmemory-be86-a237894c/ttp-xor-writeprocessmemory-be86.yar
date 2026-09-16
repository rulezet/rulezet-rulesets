rule TTP_XOR_WriteProcessMemory_be86 {
  strings:
    $key_be86 = { e9 f4 [2] db d6 [2] dd e3 [2] f3 e3 [2] cc ff }

  condition:
    any of them
}