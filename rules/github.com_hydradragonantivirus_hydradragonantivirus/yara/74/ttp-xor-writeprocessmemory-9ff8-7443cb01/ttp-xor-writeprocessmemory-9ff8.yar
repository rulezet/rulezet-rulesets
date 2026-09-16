rule TTP_XOR_WriteProcessMemory_9ff8 {
  strings:
    $key_9ff8 = { c8 8a [2] fa a8 [2] fc 9d [2] d2 9d [2] ed 81 }

  condition:
    any of them
}