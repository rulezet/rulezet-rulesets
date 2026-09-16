rule TTP_XOR_WriteProcessMemory_6e93 {
  strings:
    $key_6e93 = { 39 e1 [2] 0b c3 [2] 0d f6 [2] 23 f6 [2] 1c ea }

  condition:
    any of them
}