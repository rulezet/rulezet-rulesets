rule TTP_XOR_WriteProcessMemory_1217 {
  strings:
    $key_1217 = { 45 65 [2] 77 47 [2] 71 72 [2] 5f 72 [2] 60 6e }

  condition:
    any of them
}