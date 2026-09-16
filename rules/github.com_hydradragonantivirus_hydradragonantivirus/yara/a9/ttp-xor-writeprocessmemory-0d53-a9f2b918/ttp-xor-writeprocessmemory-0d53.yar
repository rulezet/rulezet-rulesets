rule TTP_XOR_WriteProcessMemory_0d53 {
  strings:
    $key_0d53 = { 5a 21 [2] 68 03 [2] 6e 36 [2] 40 36 [2] 7f 2a }

  condition:
    any of them
}