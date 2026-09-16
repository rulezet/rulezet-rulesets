rule TTP_XOR_WriteProcessMemory_4c68 {
  strings:
    $key_4c68 = { 1b 1a [2] 29 38 [2] 2f 0d [2] 01 0d [2] 3e 11 }

  condition:
    any of them
}