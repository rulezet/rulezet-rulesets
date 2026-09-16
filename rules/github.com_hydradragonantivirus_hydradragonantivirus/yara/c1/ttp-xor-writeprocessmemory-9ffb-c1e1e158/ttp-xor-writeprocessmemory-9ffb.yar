rule TTP_XOR_WriteProcessMemory_9ffb {
  strings:
    $key_9ffb = { c8 89 [2] fa ab [2] fc 9e [2] d2 9e [2] ed 82 }

  condition:
    any of them
}