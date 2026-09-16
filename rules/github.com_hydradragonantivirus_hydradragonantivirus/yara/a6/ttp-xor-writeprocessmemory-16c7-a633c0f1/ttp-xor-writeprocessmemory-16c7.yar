rule TTP_XOR_WriteProcessMemory_16c7 {
  strings:
    $key_16c7 = { 41 b5 [2] 73 97 [2] 75 a2 [2] 5b a2 [2] 64 be }

  condition:
    any of them
}