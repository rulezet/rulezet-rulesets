rule TTP_XOR_WriteProcessMemory_4693 {
  strings:
    $key_4693 = { 11 e1 [2] 23 c3 [2] 25 f6 [2] 0b f6 [2] 34 ea }

  condition:
    any of them
}