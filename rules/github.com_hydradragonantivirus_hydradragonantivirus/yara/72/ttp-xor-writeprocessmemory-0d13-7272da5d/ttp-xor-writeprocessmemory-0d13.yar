rule TTP_XOR_WriteProcessMemory_0d13 {
  strings:
    $key_0d13 = { 5a 61 [2] 68 43 [2] 6e 76 [2] 40 76 [2] 7f 6a }

  condition:
    any of them
}