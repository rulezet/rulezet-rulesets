rule TTP_XOR_WriteProcessMemory_9f84 {
  strings:
    $key_9f84 = { c8 f6 [2] fa d4 [2] fc e1 [2] d2 e1 [2] ed fd }

  condition:
    any of them
}