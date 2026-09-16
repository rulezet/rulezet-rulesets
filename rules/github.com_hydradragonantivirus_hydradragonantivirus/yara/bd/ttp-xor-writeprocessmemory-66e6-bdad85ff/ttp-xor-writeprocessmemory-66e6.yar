rule TTP_XOR_WriteProcessMemory_66e6 {
  strings:
    $key_66e6 = { 31 94 [2] 03 b6 [2] 05 83 [2] 2b 83 [2] 14 9f }

  condition:
    any of them
}