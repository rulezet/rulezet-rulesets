rule TTP_XOR_WriteProcessMemory_9feb {
  strings:
    $key_9feb = { c8 99 [2] fa bb [2] fc 8e [2] d2 8e [2] ed 92 }

  condition:
    any of them
}