rule TTP_XOR_WriteProcessMemory_5d68 {
  strings:
    $key_5d68 = { 0a 1a [2] 38 38 [2] 3e 0d [2] 10 0d [2] 2f 11 }

  condition:
    any of them
}