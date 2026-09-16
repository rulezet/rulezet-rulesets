rule TTP_XOR_WriteProcessMemory_ec86 {
  strings:
    $key_ec86 = { bb f4 [2] 89 d6 [2] 8f e3 [2] a1 e3 [2] 9e ff }

  condition:
    any of them
}