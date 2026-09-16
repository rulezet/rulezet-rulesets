rule TTP_XOR_WriteProcessMemory_0cf6 {
  strings:
    $key_0cf6 = { 5b 84 [2] 69 a6 [2] 6f 93 [2] 41 93 [2] 7e 8f }

  condition:
    any of them
}