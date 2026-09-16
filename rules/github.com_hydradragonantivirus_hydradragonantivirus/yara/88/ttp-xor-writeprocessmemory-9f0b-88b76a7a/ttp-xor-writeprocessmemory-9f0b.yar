rule TTP_XOR_WriteProcessMemory_9f0b {
  strings:
    $key_9f0b = { c8 79 [2] fa 5b [2] fc 6e [2] d2 6e [2] ed 72 }

  condition:
    any of them
}