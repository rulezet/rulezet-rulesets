rule TTP_XOR_WriteProcessMemory_9f6a {
  strings:
    $key_9f6a = { c8 18 [2] fa 3a [2] fc 0f [2] d2 0f [2] ed 13 }

  condition:
    any of them
}