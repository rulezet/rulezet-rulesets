rule TTP_XOR_WriteProcessMemory_9f70 {
  strings:
    $key_9f70 = { c8 02 [2] fa 20 [2] fc 15 [2] d2 15 [2] ed 09 }

  condition:
    any of them
}