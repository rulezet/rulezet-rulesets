rule TTP_XOR_WriteProcessMemory_9f83 {
  strings:
    $key_9f83 = { c8 f1 [2] fa d3 [2] fc e6 [2] d2 e6 [2] ed fa }

  condition:
    any of them
}