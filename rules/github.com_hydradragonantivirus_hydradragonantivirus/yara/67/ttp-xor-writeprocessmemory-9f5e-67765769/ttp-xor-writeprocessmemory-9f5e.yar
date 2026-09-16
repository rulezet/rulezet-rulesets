rule TTP_XOR_WriteProcessMemory_9f5e {
  strings:
    $key_9f5e = { c8 2c [2] fa 0e [2] fc 3b [2] d2 3b [2] ed 27 }

  condition:
    any of them
}