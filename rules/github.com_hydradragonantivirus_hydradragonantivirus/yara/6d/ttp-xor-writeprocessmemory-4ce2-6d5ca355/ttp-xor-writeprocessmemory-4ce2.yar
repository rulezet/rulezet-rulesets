rule TTP_XOR_WriteProcessMemory_4ce2 {
  strings:
    $key_4ce2 = { 1b 90 [2] 29 b2 [2] 2f 87 [2] 01 87 [2] 3e 9b }

  condition:
    any of them
}