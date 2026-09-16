rule TTP_XOR_WriteProcessMemory_918e {
  strings:
    $key_918e = { c6 fc [2] f4 de [2] f2 eb [2] dc eb [2] e3 f7 }

  condition:
    any of them
}