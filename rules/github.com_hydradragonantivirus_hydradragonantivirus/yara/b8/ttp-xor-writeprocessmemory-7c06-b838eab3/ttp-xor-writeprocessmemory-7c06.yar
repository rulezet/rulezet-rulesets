rule TTP_XOR_WriteProcessMemory_7c06 {
  strings:
    $key_7c06 = { 2b 74 [2] 19 56 [2] 1f 63 [2] 31 63 [2] 0e 7f }

  condition:
    any of them
}