rule TTP_XOR_WriteProcessMemory_9f62 {
  strings:
    $key_9f62 = { c8 10 [2] fa 32 [2] fc 07 [2] d2 07 [2] ed 1b }

  condition:
    any of them
}