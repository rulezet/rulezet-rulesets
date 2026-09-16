rule TTP_XOR_WriteProcessMemory_0d68 {
  strings:
    $key_0d68 = { 5a 1a [2] 68 38 [2] 6e 0d [2] 40 0d [2] 7f 11 }

  condition:
    any of them
}