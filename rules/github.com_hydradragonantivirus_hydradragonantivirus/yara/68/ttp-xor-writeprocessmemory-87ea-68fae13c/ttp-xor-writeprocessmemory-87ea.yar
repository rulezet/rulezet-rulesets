rule TTP_XOR_WriteProcessMemory_87ea {
  strings:
    $key_87ea = { d0 98 [2] e2 ba [2] e4 8f [2] ca 8f [2] f5 93 }

  condition:
    any of them
}