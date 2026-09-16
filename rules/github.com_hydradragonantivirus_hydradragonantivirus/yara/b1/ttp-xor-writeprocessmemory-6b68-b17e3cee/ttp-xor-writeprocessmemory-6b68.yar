rule TTP_XOR_WriteProcessMemory_6b68 {
  strings:
    $key_6b68 = { 3c 1a [2] 0e 38 [2] 08 0d [2] 26 0d [2] 19 11 }

  condition:
    any of them
}