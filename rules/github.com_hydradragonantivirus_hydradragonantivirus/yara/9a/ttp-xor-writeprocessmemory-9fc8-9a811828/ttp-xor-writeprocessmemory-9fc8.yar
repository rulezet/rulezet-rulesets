rule TTP_XOR_WriteProcessMemory_9fc8 {
  strings:
    $key_9fc8 = { c8 ba [2] fa 98 [2] fc ad [2] d2 ad [2] ed b1 }

  condition:
    any of them
}