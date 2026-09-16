rule TTP_XOR_WriteProcessMemory_e5a2 {
  strings:
    $key_e5a2 = { b2 d0 [2] 80 f2 [2] 86 c7 [2] a8 c7 [2] 97 db }

  condition:
    any of them
}