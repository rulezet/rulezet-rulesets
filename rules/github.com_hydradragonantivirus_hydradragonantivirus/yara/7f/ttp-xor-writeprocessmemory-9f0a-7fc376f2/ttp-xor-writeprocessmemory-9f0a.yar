rule TTP_XOR_WriteProcessMemory_9f0a {
  strings:
    $key_9f0a = { c8 78 [2] fa 5a [2] fc 6f [2] d2 6f [2] ed 73 }

  condition:
    any of them
}