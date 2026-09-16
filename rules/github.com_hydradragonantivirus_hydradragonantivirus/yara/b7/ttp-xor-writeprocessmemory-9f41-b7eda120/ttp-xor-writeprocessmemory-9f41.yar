rule TTP_XOR_WriteProcessMemory_9f41 {
  strings:
    $key_9f41 = { c8 33 [2] fa 11 [2] fc 24 [2] d2 24 [2] ed 38 }

  condition:
    any of them
}