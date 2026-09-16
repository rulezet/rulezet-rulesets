rule TTP_XOR_WriteProcessMemory_4b68 {
  strings:
    $key_4b68 = { 1c 1a [2] 2e 38 [2] 28 0d [2] 06 0d [2] 39 11 }

  condition:
    any of them
}