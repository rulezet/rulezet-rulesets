rule TTP_XOR_WriteProcessMemory_f9a9 {
  strings:
    $key_f9a9 = { ae db [2] 9c f9 [2] 9a cc [2] b4 cc [2] 8b d0 }

  condition:
    any of them
}