rule TTP_XOR_WriteProcessMemory_9f25 {
  strings:
    $key_9f25 = { c8 57 [2] fa 75 [2] fc 40 [2] d2 40 [2] ed 5c }

  condition:
    any of them
}