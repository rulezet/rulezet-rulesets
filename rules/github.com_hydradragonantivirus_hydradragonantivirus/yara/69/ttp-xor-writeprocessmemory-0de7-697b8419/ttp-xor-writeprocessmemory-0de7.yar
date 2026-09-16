rule TTP_XOR_WriteProcessMemory_0de7 {
  strings:
    $key_0de7 = { 5a 95 [2] 68 b7 [2] 6e 82 [2] 40 82 [2] 7f 9e }

  condition:
    any of them
}