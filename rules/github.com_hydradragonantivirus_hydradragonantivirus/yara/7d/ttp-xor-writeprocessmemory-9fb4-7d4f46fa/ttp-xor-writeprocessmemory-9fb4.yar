rule TTP_XOR_WriteProcessMemory_9fb4 {
  strings:
    $key_9fb4 = { c8 c6 [2] fa e4 [2] fc d1 [2] d2 d1 [2] ed cd }

  condition:
    any of them
}