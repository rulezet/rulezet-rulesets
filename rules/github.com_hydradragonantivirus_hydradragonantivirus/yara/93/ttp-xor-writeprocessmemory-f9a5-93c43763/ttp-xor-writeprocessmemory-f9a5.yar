rule TTP_XOR_WriteProcessMemory_f9a5 {
  strings:
    $key_f9a5 = { ae d7 [2] 9c f5 [2] 9a c0 [2] b4 c0 [2] 8b dc }

  condition:
    any of them
}