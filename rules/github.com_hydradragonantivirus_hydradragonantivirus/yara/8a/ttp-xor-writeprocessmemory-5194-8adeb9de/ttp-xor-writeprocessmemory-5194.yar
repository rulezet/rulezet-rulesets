rule TTP_XOR_WriteProcessMemory_5194 {
  strings:
    $key_5194 = { 06 e6 [2] 34 c4 [2] 32 f1 [2] 1c f1 [2] 23 ed }

  condition:
    any of them
}