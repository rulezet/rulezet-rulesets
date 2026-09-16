rule TTP_XOR_WriteProcessMemory_9fbe {
  strings:
    $key_9fbe = { c8 cc [2] fa ee [2] fc db [2] d2 db [2] ed c7 }

  condition:
    any of them
}