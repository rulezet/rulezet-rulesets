rule TTP_XOR_WriteProcessMemory_9f43 {
  strings:
    $key_9f43 = { c8 31 [2] fa 13 [2] fc 26 [2] d2 26 [2] ed 3a }

  condition:
    any of them
}