rule TTP_XOR_WriteProcessMemory_0d37 {
  strings:
    $key_0d37 = { 5a 45 [2] 68 67 [2] 6e 52 [2] 40 52 [2] 7f 4e }

  condition:
    any of them
}