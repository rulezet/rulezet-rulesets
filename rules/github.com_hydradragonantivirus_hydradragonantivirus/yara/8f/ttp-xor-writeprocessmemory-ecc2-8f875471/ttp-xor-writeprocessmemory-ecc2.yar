rule TTP_XOR_WriteProcessMemory_ecc2 {
  strings:
    $key_ecc2 = { bb b0 [2] 89 92 [2] 8f a7 [2] a1 a7 [2] 9e bb }

  condition:
    any of them
}