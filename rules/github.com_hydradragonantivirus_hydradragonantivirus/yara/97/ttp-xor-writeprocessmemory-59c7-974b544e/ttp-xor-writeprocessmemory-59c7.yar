rule TTP_XOR_WriteProcessMemory_59c7 {
  strings:
    $key_59c7 = { 0e b5 [2] 3c 97 [2] 3a a2 [2] 14 a2 [2] 2b be }

  condition:
    any of them
}