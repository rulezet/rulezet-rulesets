rule TTP_XOR_WriteProcessMemory_9fe7 {
  strings:
    $key_9fe7 = { c8 95 [2] fa b7 [2] fc 82 [2] d2 82 [2] ed 9e }

  condition:
    any of them
}