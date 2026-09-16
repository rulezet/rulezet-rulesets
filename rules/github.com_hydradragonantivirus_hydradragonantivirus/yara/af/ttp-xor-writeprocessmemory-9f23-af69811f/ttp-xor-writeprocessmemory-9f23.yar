rule TTP_XOR_WriteProcessMemory_9f23 {
  strings:
    $key_9f23 = { c8 51 [2] fa 73 [2] fc 46 [2] d2 46 [2] ed 5a }

  condition:
    any of them
}