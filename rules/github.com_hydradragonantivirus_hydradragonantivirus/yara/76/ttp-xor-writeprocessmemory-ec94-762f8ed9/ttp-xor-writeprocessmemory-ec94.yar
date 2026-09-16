rule TTP_XOR_WriteProcessMemory_ec94 {
  strings:
    $key_ec94 = { bb e6 [2] 89 c4 [2] 8f f1 [2] a1 f1 [2] 9e ed }

  condition:
    any of them
}