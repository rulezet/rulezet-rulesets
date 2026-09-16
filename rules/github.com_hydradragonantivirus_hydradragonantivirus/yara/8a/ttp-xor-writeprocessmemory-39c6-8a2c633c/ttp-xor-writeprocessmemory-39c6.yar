rule TTP_XOR_WriteProcessMemory_39c6 {
  strings:
    $key_39c6 = { 6e b4 [2] 5c 96 [2] 5a a3 [2] 74 a3 [2] 4b bf }

  condition:
    any of them
}