rule TTP_XOR_WriteProcessMemory_26d7 {
  strings:
    $key_26d7 = { 71 a5 [2] 43 87 [2] 45 b2 [2] 6b b2 [2] 54 ae }

  condition:
    any of them
}