rule TTP_XOR_WriteProcessMemory_99b4 {
  strings:
    $key_99b4 = { ce c6 [2] fc e4 [2] fa d1 [2] d4 d1 [2] eb cd }

  condition:
    any of them
}