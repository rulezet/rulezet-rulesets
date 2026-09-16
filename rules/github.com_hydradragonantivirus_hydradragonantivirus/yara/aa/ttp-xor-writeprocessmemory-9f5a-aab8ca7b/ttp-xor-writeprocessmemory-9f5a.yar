rule TTP_XOR_WriteProcessMemory_9f5a {
  strings:
    $key_9f5a = { c8 28 [2] fa 0a [2] fc 3f [2] d2 3f [2] ed 23 }

  condition:
    any of them
}