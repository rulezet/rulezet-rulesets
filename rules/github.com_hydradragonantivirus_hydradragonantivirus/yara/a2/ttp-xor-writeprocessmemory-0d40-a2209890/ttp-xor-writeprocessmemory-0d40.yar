rule TTP_XOR_WriteProcessMemory_0d40 {
  strings:
    $key_0d40 = { 5a 32 [2] 68 10 [2] 6e 25 [2] 40 25 [2] 7f 39 }

  condition:
    any of them
}