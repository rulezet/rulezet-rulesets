rule TTP_XOR_WriteProcessMemory_9f3f {
  strings:
    $key_9f3f = { c8 4d [2] fa 6f [2] fc 5a [2] d2 5a [2] ed 46 }

  condition:
    any of them
}