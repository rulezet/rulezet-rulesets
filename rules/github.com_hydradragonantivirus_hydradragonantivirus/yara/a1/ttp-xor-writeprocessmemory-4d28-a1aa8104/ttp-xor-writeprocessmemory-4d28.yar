rule TTP_XOR_WriteProcessMemory_4d28 {
  strings:
    $key_4d28 = { 1a 5a [2] 28 78 [2] 2e 4d [2] 00 4d [2] 3f 51 }

  condition:
    any of them
}