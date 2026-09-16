rule TTP_XOR_WriteProcessMemory_6d51 {
  strings:
    $key_6d51 = { 3a 23 [2] 08 01 [2] 0e 34 [2] 20 34 [2] 1f 28 }

  condition:
    any of them
}