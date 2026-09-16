rule TTP_XOR_WriteProcessMemory_0d73 {
  strings:
    $key_0d73 = { 5a 01 [2] 68 23 [2] 6e 16 [2] 40 16 [2] 7f 0a }

  condition:
    any of them
}