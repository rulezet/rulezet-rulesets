rule TTP_XOR_WriteProcessMemory_918a {
  strings:
    $key_918a = { c6 f8 [2] f4 da [2] f2 ef [2] dc ef [2] e3 f3 }

  condition:
    any of them
}