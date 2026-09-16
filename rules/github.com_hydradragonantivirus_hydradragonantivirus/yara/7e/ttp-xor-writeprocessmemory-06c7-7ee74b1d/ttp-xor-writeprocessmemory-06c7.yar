rule TTP_XOR_WriteProcessMemory_06c7 {
  strings:
    $key_06c7 = { 51 b5 [2] 63 97 [2] 65 a2 [2] 4b a2 [2] 74 be }

  condition:
    any of them
}