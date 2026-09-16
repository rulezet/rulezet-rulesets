rule TTP_XOR_WriteProcessMemory_9f97 {
  strings:
    $key_9f97 = { c8 e5 [2] fa c7 [2] fc f2 [2] d2 f2 [2] ed ee }

  condition:
    any of them
}