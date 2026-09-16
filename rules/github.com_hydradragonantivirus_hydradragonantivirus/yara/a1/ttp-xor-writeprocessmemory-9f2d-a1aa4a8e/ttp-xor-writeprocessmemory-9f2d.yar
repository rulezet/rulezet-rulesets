rule TTP_XOR_WriteProcessMemory_9f2d {
  strings:
    $key_9f2d = { c8 5f [2] fa 7d [2] fc 48 [2] d2 48 [2] ed 54 }

  condition:
    any of them
}