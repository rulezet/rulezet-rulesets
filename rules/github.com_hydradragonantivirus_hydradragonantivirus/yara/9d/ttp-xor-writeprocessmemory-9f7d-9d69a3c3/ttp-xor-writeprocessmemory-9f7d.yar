rule TTP_XOR_WriteProcessMemory_9f7d {
  strings:
    $key_9f7d = { c8 0f [2] fa 2d [2] fc 18 [2] d2 18 [2] ed 04 }

  condition:
    any of them
}