rule TTP_XOR_WriteProcessMemory_9fa3 {
  strings:
    $key_9fa3 = { c8 d1 [2] fa f3 [2] fc c6 [2] d2 c6 [2] ed da }

  condition:
    any of them
}