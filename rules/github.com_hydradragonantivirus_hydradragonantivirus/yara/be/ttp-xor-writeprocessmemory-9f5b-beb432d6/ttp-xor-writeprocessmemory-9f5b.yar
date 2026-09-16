rule TTP_XOR_WriteProcessMemory_9f5b {
  strings:
    $key_9f5b = { c8 29 [2] fa 0b [2] fc 3e [2] d2 3e [2] ed 22 }

  condition:
    any of them
}