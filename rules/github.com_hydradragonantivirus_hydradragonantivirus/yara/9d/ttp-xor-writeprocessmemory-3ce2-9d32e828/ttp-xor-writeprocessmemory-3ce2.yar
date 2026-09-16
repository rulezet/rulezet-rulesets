rule TTP_XOR_WriteProcessMemory_3ce2 {
  strings:
    $key_3ce2 = { 6b 90 [2] 59 b2 [2] 5f 87 [2] 71 87 [2] 4e 9b }

  condition:
    any of them
}