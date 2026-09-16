rule TTP_XOR_WriteProcessMemory_7b68 {
  strings:
    $key_7b68 = { 2c 1a [2] 1e 38 [2] 18 0d [2] 36 0d [2] 09 11 }

  condition:
    any of them
}