rule TTP_XOR_WriteProcessMemory_9f0c {
  strings:
    $key_9f0c = { c8 7e [2] fa 5c [2] fc 69 [2] d2 69 [2] ed 75 }

  condition:
    any of them
}