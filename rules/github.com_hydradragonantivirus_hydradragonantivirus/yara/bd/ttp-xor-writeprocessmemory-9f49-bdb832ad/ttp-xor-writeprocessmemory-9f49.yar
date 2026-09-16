rule TTP_XOR_WriteProcessMemory_9f49 {
  strings:
    $key_9f49 = { c8 3b [2] fa 19 [2] fc 2c [2] d2 2c [2] ed 30 }

  condition:
    any of them
}