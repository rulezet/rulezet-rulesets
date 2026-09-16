rule TTP_XOR_WriteProcessMemory_99b1 {
  strings:
    $key_99b1 = { ce c3 [2] fc e1 [2] fa d4 [2] d4 d4 [2] eb c8 }

  condition:
    any of them
}