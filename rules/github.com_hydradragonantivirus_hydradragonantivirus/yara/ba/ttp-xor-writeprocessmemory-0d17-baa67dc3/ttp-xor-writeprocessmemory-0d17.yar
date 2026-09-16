rule TTP_XOR_WriteProcessMemory_0d17 {
  strings:
    $key_0d17 = { 5a 65 [2] 68 47 [2] 6e 72 [2] 40 72 [2] 7f 6e }

  condition:
    any of them
}