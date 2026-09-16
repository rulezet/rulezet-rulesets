rule TTP_XOR_WriteProcessMemory_6dd7 {
  strings:
    $key_6dd7 = { 3a a5 [2] 08 87 [2] 0e b2 [2] 20 b2 [2] 1f ae }

  condition:
    any of them
}