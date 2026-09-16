rule TTP_XOR_WriteProcessMemory_9f00 {
  strings:
    $key_9f00 = { c8 72 [2] fa 50 [2] fc 65 [2] d2 65 [2] ed 79 }

  condition:
    any of them
}