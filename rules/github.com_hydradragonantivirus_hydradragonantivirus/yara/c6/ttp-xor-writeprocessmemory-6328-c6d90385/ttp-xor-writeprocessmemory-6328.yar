rule TTP_XOR_WriteProcessMemory_6328 {
  strings:
    $key_6328 = { 34 5a [2] 06 78 [2] 00 4d [2] 2e 4d [2] 11 51 }

  condition:
    any of them
}