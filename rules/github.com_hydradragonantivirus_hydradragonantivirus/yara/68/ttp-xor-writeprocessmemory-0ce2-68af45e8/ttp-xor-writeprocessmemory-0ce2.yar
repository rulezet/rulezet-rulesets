rule TTP_XOR_WriteProcessMemory_0ce2 {
  strings:
    $key_0ce2 = { 5b 90 [2] 69 b2 [2] 6f 87 [2] 41 87 [2] 7e 9b }

  condition:
    any of them
}