rule TTP_XOR_WriteProcessMemory_9f68 {
  strings:
    $key_9f68 = { c8 1a [2] fa 38 [2] fc 0d [2] d2 0d [2] ed 11 }

  condition:
    any of them
}