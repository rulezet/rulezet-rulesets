rule TTP_XOR_WriteProcessMemory_9f5c {
  strings:
    $key_9f5c = { c8 2e [2] fa 0c [2] fc 39 [2] d2 39 [2] ed 25 }

  condition:
    any of them
}