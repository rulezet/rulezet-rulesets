rule TTP_XOR_WriteProcessMemory_0d63 {
  strings:
    $key_0d63 = { 5a 11 [2] 68 33 [2] 6e 06 [2] 40 06 [2] 7f 1a }

  condition:
    any of them
}