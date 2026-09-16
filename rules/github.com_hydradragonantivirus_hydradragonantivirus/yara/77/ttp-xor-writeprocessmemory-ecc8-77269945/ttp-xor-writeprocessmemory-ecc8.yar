rule TTP_XOR_WriteProcessMemory_ecc8 {
  strings:
    $key_ecc8 = { bb ba [2] 89 98 [2] 8f ad [2] a1 ad [2] 9e b1 }

  condition:
    any of them
}