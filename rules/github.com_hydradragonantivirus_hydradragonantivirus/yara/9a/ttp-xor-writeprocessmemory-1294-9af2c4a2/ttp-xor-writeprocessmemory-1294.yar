rule TTP_XOR_WriteProcessMemory_1294 {
  strings:
    $key_1294 = { 45 e6 [2] 77 c4 [2] 71 f1 [2] 5f f1 [2] 60 ed }

  condition:
    any of them
}