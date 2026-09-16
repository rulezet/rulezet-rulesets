rule TTP_XOR_WriteProcessMemory_7c51 {
  strings:
    $key_7c51 = { 2b 23 [2] 19 01 [2] 1f 34 [2] 31 34 [2] 0e 28 }

  condition:
    any of them
}