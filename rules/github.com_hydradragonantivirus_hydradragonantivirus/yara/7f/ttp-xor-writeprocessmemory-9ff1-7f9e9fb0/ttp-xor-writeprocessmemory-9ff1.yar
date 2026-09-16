rule TTP_XOR_WriteProcessMemory_9ff1 {
  strings:
    $key_9ff1 = { c8 83 [2] fa a1 [2] fc 94 [2] d2 94 [2] ed 88 }

  condition:
    any of them
}