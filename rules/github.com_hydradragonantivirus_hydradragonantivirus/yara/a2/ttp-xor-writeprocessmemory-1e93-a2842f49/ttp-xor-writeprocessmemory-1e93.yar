rule TTP_XOR_WriteProcessMemory_1e93 {
  strings:
    $key_1e93 = { 49 e1 [2] 7b c3 [2] 7d f6 [2] 53 f6 [2] 6c ea }

  condition:
    any of them
}