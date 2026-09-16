rule TTP_XOR_WriteProcessMemory_be97 {
  strings:
    $key_be97 = { e9 e5 [2] db c7 [2] dd f2 [2] f3 f2 [2] cc ee }

  condition:
    any of them
}