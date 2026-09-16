rule TTP_XOR_WriteProcessMemory_9f46 {
  strings:
    $key_9f46 = { c8 34 [2] fa 16 [2] fc 23 [2] d2 23 [2] ed 3f }

  condition:
    any of them
}