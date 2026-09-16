rule TTP_XOR_WriteProcessMemory_9fff {
  strings:
    $key_9fff = { c8 8d [2] fa af [2] fc 9a [2] d2 9a [2] ed 86 }

  condition:
    any of them
}