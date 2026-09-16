rule TTP_XOR_WriteProcessMemory_4ded {
  strings:
    $key_4ded = { 1a 9f [2] 28 bd [2] 2e 88 [2] 00 88 [2] 3f 94 }

  condition:
    any of them
}