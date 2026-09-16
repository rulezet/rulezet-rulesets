rule TTP_XOR_WriteProcessMemory_9f3a {
  strings:
    $key_9f3a = { c8 48 [2] fa 6a [2] fc 5f [2] d2 5f [2] ed 43 }

  condition:
    any of them
}