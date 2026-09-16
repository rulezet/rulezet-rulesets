rule TTP_XOR_WriteProcessMemory_9f7b {
  strings:
    $key_9f7b = { c8 09 [2] fa 2b [2] fc 1e [2] d2 1e [2] ed 02 }

  condition:
    any of them
}