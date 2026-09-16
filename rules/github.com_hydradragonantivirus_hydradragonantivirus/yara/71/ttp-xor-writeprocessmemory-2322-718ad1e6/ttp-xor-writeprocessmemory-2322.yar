rule TTP_XOR_WriteProcessMemory_2322 {
  strings:
    $key_2322 = { 74 50 [2] 46 72 [2] 40 47 [2] 6e 47 [2] 51 5b }

  condition:
    any of them
}