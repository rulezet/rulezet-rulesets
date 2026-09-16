rule TTP_XOR_WriteProcessMemory_2294 {
  strings:
    $key_2294 = { 75 e6 [2] 47 c4 [2] 41 f1 [2] 6f f1 [2] 50 ed }

  condition:
    any of them
}