rule TTP_XOR_WriteProcessMemory_7294 {
  strings:
    $key_7294 = { 25 e6 [2] 17 c4 [2] 11 f1 [2] 3f f1 [2] 00 ed }

  condition:
    any of them
}