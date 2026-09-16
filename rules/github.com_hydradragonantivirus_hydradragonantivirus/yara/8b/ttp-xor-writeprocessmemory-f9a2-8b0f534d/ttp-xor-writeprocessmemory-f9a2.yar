rule TTP_XOR_WriteProcessMemory_f9a2 {
  strings:
    $key_f9a2 = { ae d0 [2] 9c f2 [2] 9a c7 [2] b4 c7 [2] 8b db }

  condition:
    any of them
}