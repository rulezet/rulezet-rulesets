rule TTP_XOR_WriteProcessMemory_24c7 {
  strings:
    $key_24c7 = { 73 b5 [2] 41 97 [2] 47 a2 [2] 69 a2 [2] 56 be }

  condition:
    any of them
}