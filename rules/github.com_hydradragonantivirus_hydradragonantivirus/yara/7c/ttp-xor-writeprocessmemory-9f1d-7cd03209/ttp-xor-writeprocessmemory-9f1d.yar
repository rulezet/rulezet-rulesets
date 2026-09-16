rule TTP_XOR_WriteProcessMemory_9f1d {
  strings:
    $key_9f1d = { c8 6f [2] fa 4d [2] fc 78 [2] d2 78 [2] ed 64 }

  condition:
    any of them
}