rule TTP_XOR_WriteProcessMemory_a6c7 {
  strings:
    $key_a6c7 = { f1 b5 [2] c3 97 [2] c5 a2 [2] eb a2 [2] d4 be }

  condition:
    any of them
}