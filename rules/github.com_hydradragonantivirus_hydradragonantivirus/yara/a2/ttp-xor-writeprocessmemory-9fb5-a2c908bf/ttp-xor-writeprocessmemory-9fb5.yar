rule TTP_XOR_WriteProcessMemory_9fb5 {
  strings:
    $key_9fb5 = { c8 c7 [2] fa e5 [2] fc d0 [2] d2 d0 [2] ed cc }

  condition:
    any of them
}