rule TTP_XOR_WriteProcessMemory_9ff0 {
  strings:
    $key_9ff0 = { c8 82 [2] fa a0 [2] fc 95 [2] d2 95 [2] ed 89 }

  condition:
    any of them
}