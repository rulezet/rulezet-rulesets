rule TTP_XOR_WriteProcessMemory_6d68 {
  strings:
    $key_6d68 = { 3a 1a [2] 08 38 [2] 0e 0d [2] 20 0d [2] 1f 11 }

  condition:
    any of them
}