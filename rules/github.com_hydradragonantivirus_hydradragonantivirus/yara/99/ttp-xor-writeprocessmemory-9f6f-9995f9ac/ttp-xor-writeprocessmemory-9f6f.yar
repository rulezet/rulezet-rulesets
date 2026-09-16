rule TTP_XOR_WriteProcessMemory_9f6f {
  strings:
    $key_9f6f = { c8 1d [2] fa 3f [2] fc 0a [2] d2 0a [2] ed 16 }

  condition:
    any of them
}