rule TTP_XOR_WriteProcessMemory_2e93 {
  strings:
    $key_2e93 = { 79 e1 [2] 4b c3 [2] 4d f6 [2] 63 f6 [2] 5c ea }

  condition:
    any of them
}