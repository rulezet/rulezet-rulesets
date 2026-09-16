rule TTP_XOR_WriteProcessMemory_9f59 {
  strings:
    $key_9f59 = { c8 2b [2] fa 09 [2] fc 3c [2] d2 3c [2] ed 20 }

  condition:
    any of them
}