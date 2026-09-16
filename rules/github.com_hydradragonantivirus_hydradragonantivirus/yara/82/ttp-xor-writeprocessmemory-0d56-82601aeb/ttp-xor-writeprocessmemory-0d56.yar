rule TTP_XOR_WriteProcessMemory_0d56 {
  strings:
    $key_0d56 = { 5a 24 [2] 68 06 [2] 6e 33 [2] 40 33 [2] 7f 2f }

  condition:
    any of them
}