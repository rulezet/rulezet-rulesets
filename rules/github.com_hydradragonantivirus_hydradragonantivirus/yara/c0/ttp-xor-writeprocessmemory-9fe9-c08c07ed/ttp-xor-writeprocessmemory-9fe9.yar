rule TTP_XOR_WriteProcessMemory_9fe9 {
  strings:
    $key_9fe9 = { c8 9b [2] fa b9 [2] fc 8c [2] d2 8c [2] ed 90 }

  condition:
    any of them
}