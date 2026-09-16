rule TTP_XOR_WriteProcessMemory_5d51 {
  strings:
    $key_5d51 = { 0a 23 [2] 38 01 [2] 3e 34 [2] 10 34 [2] 2f 28 }

  condition:
    any of them
}