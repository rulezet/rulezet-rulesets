rule TTP_XOR_WriteProcessMemory_5d41 {
  strings:
    $key_5d41 = { 0a 33 [2] 38 11 [2] 3e 24 [2] 10 24 [2] 2f 38 }

  condition:
    any of them
}