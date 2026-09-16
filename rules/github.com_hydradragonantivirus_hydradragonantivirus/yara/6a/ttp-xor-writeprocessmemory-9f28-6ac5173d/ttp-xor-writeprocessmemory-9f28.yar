rule TTP_XOR_WriteProcessMemory_9f28 {
  strings:
    $key_9f28 = { c8 5a [2] fa 78 [2] fc 4d [2] d2 4d [2] ed 51 }

  condition:
    any of them
}