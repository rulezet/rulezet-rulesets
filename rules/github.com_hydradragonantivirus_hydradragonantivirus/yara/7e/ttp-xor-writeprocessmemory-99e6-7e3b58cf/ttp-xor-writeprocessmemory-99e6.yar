rule TTP_XOR_WriteProcessMemory_99e6 {
  strings:
    $key_99e6 = { ce 94 [2] fc b6 [2] fa 83 [2] d4 83 [2] eb 9f }

  condition:
    any of them
}