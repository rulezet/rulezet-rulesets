rule TTP_XOR_WriteProcessMemory_ecc3 {
  strings:
    $key_ecc3 = { bb b1 [2] 89 93 [2] 8f a6 [2] a1 a6 [2] 9e ba }

  condition:
    any of them
}