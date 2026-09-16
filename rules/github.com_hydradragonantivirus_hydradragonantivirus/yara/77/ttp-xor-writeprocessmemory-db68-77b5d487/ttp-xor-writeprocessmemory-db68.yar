rule TTP_XOR_WriteProcessMemory_db68 {
  strings:
    $key_db68 = { 8c 1a [2] be 38 [2] b8 0d [2] 96 0d [2] a9 11 }

  condition:
    any of them
}