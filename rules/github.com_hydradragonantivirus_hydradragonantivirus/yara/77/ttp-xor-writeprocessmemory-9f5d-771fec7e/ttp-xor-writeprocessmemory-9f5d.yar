rule TTP_XOR_WriteProcessMemory_9f5d {
  strings:
    $key_9f5d = { c8 2f [2] fa 0d [2] fc 38 [2] d2 38 [2] ed 24 }

  condition:
    any of them
}