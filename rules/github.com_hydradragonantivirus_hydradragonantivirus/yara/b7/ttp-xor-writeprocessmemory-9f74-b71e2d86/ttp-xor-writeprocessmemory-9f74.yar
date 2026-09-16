rule TTP_XOR_WriteProcessMemory_9f74 {
  strings:
    $key_9f74 = { c8 06 [2] fa 24 [2] fc 11 [2] d2 11 [2] ed 0d }

  condition:
    any of them
}