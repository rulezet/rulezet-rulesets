rule TTP_XOR_WriteProcessMemory_36c4 {
  strings:
    $key_36c4 = { 61 b6 [2] 53 94 [2] 55 a1 [2] 7b a1 [2] 44 bd }

  condition:
    any of them
}