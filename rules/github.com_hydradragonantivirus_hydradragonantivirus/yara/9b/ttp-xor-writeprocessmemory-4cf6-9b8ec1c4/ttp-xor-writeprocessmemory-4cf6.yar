rule TTP_XOR_WriteProcessMemory_4cf6 {
  strings:
    $key_4cf6 = { 1b 84 [2] 29 a6 [2] 2f 93 [2] 01 93 [2] 3e 8f }

  condition:
    any of them
}