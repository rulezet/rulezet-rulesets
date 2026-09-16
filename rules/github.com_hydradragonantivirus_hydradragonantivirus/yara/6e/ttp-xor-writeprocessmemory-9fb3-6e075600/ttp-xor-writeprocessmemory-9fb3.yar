rule TTP_XOR_WriteProcessMemory_9fb3 {
  strings:
    $key_9fb3 = { c8 c1 [2] fa e3 [2] fc d6 [2] d2 d6 [2] ed ca }

  condition:
    any of them
}