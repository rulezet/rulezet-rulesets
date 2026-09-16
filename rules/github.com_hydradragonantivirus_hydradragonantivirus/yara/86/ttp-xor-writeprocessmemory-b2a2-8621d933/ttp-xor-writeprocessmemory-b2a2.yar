rule TTP_XOR_WriteProcessMemory_b2a2 {
  strings:
    $key_b2a2 = { e5 d0 [2] d7 f2 [2] d1 c7 [2] ff c7 [2] c0 db }

  condition:
    any of them
}