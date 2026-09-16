rule TTP_XOR_WriteProcessMemory_99e2 {
  strings:
    $key_99e2 = { ce 90 [2] fc b2 [2] fa 87 [2] d4 87 [2] eb 9b }

  condition:
    any of them
}