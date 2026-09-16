rule TTP_XOR_WriteProcessMemory_9f86 {
  strings:
    $key_9f86 = { c8 f4 [2] fa d6 [2] fc e3 [2] d2 e3 [2] ed ff }

  condition:
    any of them
}