rule TTP_XOR_WriteProcessMemory_860e {
  strings:
    $key_860e = { d1 7c [2] e3 5e [2] e5 6b [2] cb 6b [2] f4 77 }

  condition:
    any of them
}