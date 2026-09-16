rule TTP_XOR_WriteProcessMemory_9f87 {
  strings:
    $key_9f87 = { c8 f5 [2] fa d7 [2] fc e2 [2] d2 e2 [2] ed fe }

  condition:
    any of them
}