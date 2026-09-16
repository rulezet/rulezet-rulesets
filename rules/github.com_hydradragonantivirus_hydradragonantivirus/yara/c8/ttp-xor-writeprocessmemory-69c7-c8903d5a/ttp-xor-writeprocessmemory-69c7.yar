rule TTP_XOR_WriteProcessMemory_69c7 {
  strings:
    $key_69c7 = { 3e b5 [2] 0c 97 [2] 0a a2 [2] 24 a2 [2] 1b be }

  condition:
    any of them
}