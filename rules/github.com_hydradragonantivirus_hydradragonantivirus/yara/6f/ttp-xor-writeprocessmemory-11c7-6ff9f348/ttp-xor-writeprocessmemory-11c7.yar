rule TTP_XOR_WriteProcessMemory_11c7 {
  strings:
    $key_11c7 = { 46 b5 [2] 74 97 [2] 72 a2 [2] 5c a2 [2] 63 be }

  condition:
    any of them
}