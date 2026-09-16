rule TTP_XOR_WriteProcessMemory_9fee {
  strings:
    $key_9fee = { c8 9c [2] fa be [2] fc 8b [2] d2 8b [2] ed 97 }

  condition:
    any of them
}