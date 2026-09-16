rule TTP_XOR_WriteProcessMemory_99d9 {
  strings:
    $key_99d9 = { ce ab [2] fc 89 [2] fa bc [2] d4 bc [2] eb a0 }

  condition:
    any of them
}