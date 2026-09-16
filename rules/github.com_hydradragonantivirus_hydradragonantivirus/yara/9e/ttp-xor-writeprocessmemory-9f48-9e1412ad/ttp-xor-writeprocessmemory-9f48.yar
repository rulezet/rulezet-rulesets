rule TTP_XOR_WriteProcessMemory_9f48 {
  strings:
    $key_9f48 = { c8 3a [2] fa 18 [2] fc 2d [2] d2 2d [2] ed 31 }

  condition:
    any of them
}