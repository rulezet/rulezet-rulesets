rule TTP_XOR_WriteProcessMemory_5d37 {
  strings:
    $key_5d37 = { 0a 45 [2] 38 67 [2] 3e 52 [2] 10 52 [2] 2f 4e }

  condition:
    any of them
}