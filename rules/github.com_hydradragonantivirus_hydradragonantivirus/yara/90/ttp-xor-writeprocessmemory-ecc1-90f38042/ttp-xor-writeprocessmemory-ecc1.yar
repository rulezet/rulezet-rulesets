rule TTP_XOR_WriteProcessMemory_ecc1 {
  strings:
    $key_ecc1 = { bb b3 [2] 89 91 [2] 8f a4 [2] a1 a4 [2] 9e b8 }

  condition:
    any of them
}