rule TTP_XOR_WriteProcessMemory_9f1b {
  strings:
    $key_9f1b = { c8 69 [2] fa 4b [2] fc 7e [2] d2 7e [2] ed 62 }

  condition:
    any of them
}