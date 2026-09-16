rule TTP_XOR_WriteProcessMemory_2332 {
  strings:
    $key_2332 = { 74 40 [2] 46 62 [2] 40 57 [2] 6e 57 [2] 51 4b }

  condition:
    any of them
}