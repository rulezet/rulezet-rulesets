rule TTP_XOR_WriteProcessMemory_4d23 {
  strings:
    $key_4d23 = { 1a 51 [2] 28 73 [2] 2e 46 [2] 00 46 [2] 3f 5a }

  condition:
    any of them
}