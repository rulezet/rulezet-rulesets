rule TTP_XOR_WriteProcessMemory_5422 {
  strings:
    $key_5422 = { 03 50 [2] 31 72 [2] 37 47 [2] 19 47 [2] 26 5b }

  condition:
    any of them
}