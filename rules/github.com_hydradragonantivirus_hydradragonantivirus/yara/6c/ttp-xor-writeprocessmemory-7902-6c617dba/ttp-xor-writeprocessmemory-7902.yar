rule TTP_XOR_WriteProcessMemory_7902 {
  strings:
    $key_7902 = { 2e 70 [2] 1c 52 [2] 1a 67 [2] 34 67 [2] 0b 7b }

  condition:
    any of them
}