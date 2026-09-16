rule TTP_XOR_WriteProcessMemory_99b0 {
  strings:
    $key_99b0 = { ce c2 [2] fc e0 [2] fa d5 [2] d4 d5 [2] eb c9 }

  condition:
    any of them
}