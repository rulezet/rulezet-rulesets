rule TTP_XOR_WriteProcessMemory_9f0f {
  strings:
    $key_9f0f = { c8 7d [2] fa 5f [2] fc 6a [2] d2 6a [2] ed 76 }

  condition:
    any of them
}