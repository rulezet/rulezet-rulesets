rule TTP_XOR_WriteProcessMemory_39c1 {
  strings:
    $key_39c1 = { 6e b3 [2] 5c 91 [2] 5a a4 [2] 74 a4 [2] 4b b8 }

  condition:
    any of them
}