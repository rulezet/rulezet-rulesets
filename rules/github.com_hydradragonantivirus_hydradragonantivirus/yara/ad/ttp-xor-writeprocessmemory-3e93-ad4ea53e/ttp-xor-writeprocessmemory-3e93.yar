rule TTP_XOR_WriteProcessMemory_3e93 {
  strings:
    $key_3e93 = { 69 e1 [2] 5b c3 [2] 5d f6 [2] 73 f6 [2] 4c ea }

  condition:
    any of them
}