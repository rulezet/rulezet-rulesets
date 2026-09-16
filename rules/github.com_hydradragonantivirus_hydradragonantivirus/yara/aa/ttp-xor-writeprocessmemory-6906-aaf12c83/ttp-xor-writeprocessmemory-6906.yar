rule TTP_XOR_WriteProcessMemory_6906 {
  strings:
    $key_6906 = { 3e 74 [2] 0c 56 [2] 0a 63 [2] 24 63 [2] 1b 7f }

  condition:
    any of them
}