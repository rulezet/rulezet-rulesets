rule TTP_XOR_WriteProcessMemory_918c {
  strings:
    $key_918c = { c6 fe [2] f4 dc [2] f2 e9 [2] dc e9 [2] e3 f5 }

  condition:
    any of them
}