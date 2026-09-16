rule TTP_XOR_WriteProcessMemory_9fa7 {
  strings:
    $key_9fa7 = { c8 d5 [2] fa f7 [2] fc c2 [2] d2 c2 [2] ed de }

  condition:
    any of them
}