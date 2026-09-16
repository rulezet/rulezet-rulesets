rule TTP_XOR_WriteProcessMemory_9f2b {
  strings:
    $key_9f2b = { c8 59 [2] fa 7b [2] fc 4e [2] d2 4e [2] ed 52 }

  condition:
    any of them
}