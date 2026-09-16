rule TTP_XOR_WriteProcessMemory_4de3 {
  strings:
    $key_4de3 = { 1a 91 [2] 28 b3 [2] 2e 86 [2] 00 86 [2] 3f 9a }

  condition:
    any of them
}