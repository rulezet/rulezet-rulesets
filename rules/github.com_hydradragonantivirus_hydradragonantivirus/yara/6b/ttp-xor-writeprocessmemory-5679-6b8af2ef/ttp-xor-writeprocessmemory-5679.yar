rule TTP_XOR_WriteProcessMemory_5679 {
  strings:
    $key_5679 = { 01 0b [2] 33 29 [2] 35 1c [2] 1b 1c [2] 24 00 }

  condition:
    any of them
}