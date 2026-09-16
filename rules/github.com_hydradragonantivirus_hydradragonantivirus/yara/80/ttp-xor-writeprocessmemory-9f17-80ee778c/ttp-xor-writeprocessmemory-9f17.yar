rule TTP_XOR_WriteProcessMemory_9f17 {
  strings:
    $key_9f17 = { c8 65 [2] fa 47 [2] fc 72 [2] d2 72 [2] ed 6e }

  condition:
    any of them
}