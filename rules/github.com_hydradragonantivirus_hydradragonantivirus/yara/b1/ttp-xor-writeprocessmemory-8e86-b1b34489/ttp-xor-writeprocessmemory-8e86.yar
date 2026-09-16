rule TTP_XOR_WriteProcessMemory_8e86 {
  strings:
    $key_8e86 = { d9 f4 [2] eb d6 [2] ed e3 [2] c3 e3 [2] fc ff }

  condition:
    any of them
}