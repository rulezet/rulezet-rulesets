rule TTP_XOR_WriteProcessMemory_9f7e {
  strings:
    $key_9f7e = { c8 0c [2] fa 2e [2] fc 1b [2] d2 1b [2] ed 07 }

  condition:
    any of them
}