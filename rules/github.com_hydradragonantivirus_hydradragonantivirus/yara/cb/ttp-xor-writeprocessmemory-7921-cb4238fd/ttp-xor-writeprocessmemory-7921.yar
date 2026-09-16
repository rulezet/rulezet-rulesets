rule TTP_XOR_WriteProcessMemory_7921 {
  strings:
    $key_7921 = { 2e 53 [2] 1c 71 [2] 1a 44 [2] 34 44 [2] 0b 58 }

  condition:
    any of them
}