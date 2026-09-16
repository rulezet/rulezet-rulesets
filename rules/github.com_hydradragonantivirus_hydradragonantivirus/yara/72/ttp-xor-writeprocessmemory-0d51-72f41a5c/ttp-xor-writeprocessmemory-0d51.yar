rule TTP_XOR_WriteProcessMemory_0d51 {
  strings:
    $key_0d51 = { 5a 23 [2] 68 01 [2] 6e 34 [2] 40 34 [2] 7f 28 }

  condition:
    any of them
}