rule TTP_XOR_WriteProcessMemory_4d0d {
  strings:
    $key_4d0d = { 1a 7f [2] 28 5d [2] 2e 68 [2] 00 68 [2] 3f 74 }

  condition:
    any of them
}