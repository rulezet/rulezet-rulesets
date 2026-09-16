rule TTP_XOR_WriteProcessMemory_4522 {
  strings:
    $key_4522 = { 12 50 [2] 20 72 [2] 26 47 [2] 08 47 [2] 37 5b }

  condition:
    any of them
}